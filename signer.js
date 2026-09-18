/**
 * Dynamic MPC signing sidecar for musemaxxing agent wallets.
 *
 * Listens on 127.0.0.1 only. The FastAPI backend (which holds the Dynamic
 * credential) performs `waas/authenticate` for the agent's Dynamic user and
 * passes the short-lived JWT here. This process uses Dynamic's official Node
 * SDK (@dynamic-labs-wallet/node-evm) to run the MPC signing ceremony and
 * returns the signed raw transaction. It never broadcasts.
 *
 * No raw private keys exist anywhere in this flow: signing is a 2-of-2
 * threshold ceremony between this client and Dynamic's MPC relay.
 *
 * Env:
 *   SIDECAR_TOKEN        Bearer token the backend must present (required)
 *   DYNAMIC_ENVIRONMENT_ID  Dynamic environment id (default: musemaxxing prod)
 *   PORT                 default 8787
 *   ROBINHOOD_RPC        default https://rpc.mainnet.chain.robinhood.com
 */
'use strict';

const http = require('http');
const crypto = require('crypto');

const { DynamicEvmWalletClient } = require('@dynamic-labs-wallet/node-evm');
const { createPublicClient, http: viemHttp, keccak256 } = require('viem');

const ENVIRONMENT_ID = process.env.DYNAMIC_ENVIRONMENT_ID || '91d2182c-c794-4a7e-9c72-54ec2747d5cd';
const ROBINHOOD_RPC = process.env.ROBINHOOD_RPC || 'https://rpc.mainnet.chain.robinhood.com';
const CHAIN_ID = 4663; // Robinhood Chain — the only chain this sidecar will sign for
const PORT = parseInt(process.env.PORT || '8787', 10);
// Railway / production containers need 0.0.0.0; local dev stays on loopback.
const HOST = process.env.SIDECAR_HOST || '127.0.0.1';

const SIDECAR_TOKEN = process.env.SIDECAR_TOKEN;
if (!SIDECAR_TOKEN) {
  console.error('FATAL: SIDECAR_TOKEN env var is required');
  process.exit(1);
}

const publicClient = createPublicClient({ transport: viemHttp(ROBINHOOD_RPC) });

function timingSafeEqual(a, b) {
  const ab = Buffer.from(a || '', 'utf8');
  const bb = Buffer.from(b || '', 'utf8');
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', (c) => {
      raw += c;
      if (raw.length > 65536) reject(new Error('body too large'));
    });
    req.on('end', () => resolve(raw));
    req.on('error', reject);
  });
}

function send(res, status, obj) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(obj));
}

function isAddress(s) {
  return typeof s === 'string' && /^0x[0-9a-fA-F]{40}$/.test(s);
}

/**
 * Exchange a Dynamic API token for a JWT via waas/authenticate.
 * Used for backend-initiated signing where no user JWT is available.
 * 
 * Endpoint: POST https://app.dynamicauth.com/api/v0/environments/{envId}/waas/authenticate
 * The API token must have the 'waas.authenticate' scope (set in Dynamic dashboard).
 * Returns the JWT from encodedJwts.jwt.
 */
async function _getJwtViaApiToken(apiToken) {
  const https = require('https');
  const envId = process.env.DYNAMIC_ENVIRONMENT_ID || '91d2182c-c794-4a7e-9c72-54ec2747d5cd';
  return new Promise((resolve, reject) => {
    const data = JSON.stringify({});
    const req = https.request({
      hostname: 'app.dynamicauth.com',
      path: `/api/v0/environments/${envId}/waas/authenticate`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiToken}`,
        'Content-Length': Buffer.byteLength(data),
      },
    }, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(body);
          // JWT is in encodedJwts.jwt per Dynamic docs.
          const token = (json.encodedJwts && json.encodedJwts.jwt) || json.token || json.jwt;
          if (!token) {
            reject({ status: 500, code: 'auth_failed', message: `waas/authenticate did not return a token: ${body.slice(0, 300)}` });
            return;
          }
          resolve(token);
        } catch (e) {
          reject({ status: 500, code: 'auth_failed', message: `waas/authenticate invalid response: ${body.slice(0, 300)}` });
        }
      });
    });
    req.on('error', (e) => {
      reject({ status: 500, code: 'auth_failed', message: `waas/authenticate request failed: ${e.message}` });
    });
    req.write(data);
    req.end();
  });
}

async function handleSign(body) {
  const { jwt, useApiToken, walletId, accountAddress, to, valueWei, data, walletMetadata: md } = body || {};
  // Test-only escape hatch, gated by environment (never by request): lets us
  // verify the MPC ceremony against wallets with no ETH without funding them.
  // Production sets ALLOW_TEST_SIGNING=false (default); the request flag is ignored.
  const allowInsufficientFunds =
    process.env.ALLOW_TEST_SIGNING === 'true' && body && body.allowInsufficientFunds === true;
  // JWT validation is handled below in the authJwt logic.
  if (!walletId || typeof walletId !== 'string') throw { status: 400, code: 'bad_wallet', message: 'walletId is required' };
  if (!isAddress(accountAddress)) throw { status: 400, code: 'bad_wallet', message: 'accountAddress must be a 0x address' };
  if (!isAddress(to)) throw { status: 400, code: 'bad_recipient', message: 'to must be a 0x address' };
  if (/^0x0{40}$/i.test(to)) throw { status: 400, code: 'bad_recipient', message: 'to must not be the zero address' };
  let value;
  try {
    value = BigInt(valueWei || '0');
  } catch {
    throw { status: 400, code: 'bad_value', message: 'valueWei must be a decimal wei string' };
  }
  if (value < 0n) throw { status: 400, code: 'bad_value', message: 'valueWei must be >= 0' };
  let txData = '0x';
  if (data !== undefined && data !== null && data !== '0x' && data !== '') {
    if (typeof data !== 'string' || !/^0x[0-9a-fA-F]*$/.test(data) || data.length > 2 + 8 + 64 * 4) {
      // cap calldata at ~4 ABI words + selector; v1 supports plain/ERC-20 transfers only
      throw { status: 400, code: 'bad_data', message: 'data must be 0x hex (v1: plain or ERC-20 transfer calldata only)' };
    }
    txData = data;
  }

  let authJwt = jwt;
  if (useApiToken) {
    // Backend-initiated signing: get a JWT via Dynamic's waas/authenticate
    // using the sidecar's API token, then use the standard SDK auth flow.
    const apiToken = process.env.DYNAMIC_API_TOKEN;
    if (!apiToken) throw { status: 500, code: 'no_api_token', message: 'DYNAMIC_API_TOKEN not configured' };
    authJwt = await _getJwtViaApiToken(apiToken);
  } else {
    if (!authJwt || typeof authJwt !== 'string') {
      throw { status: 400, code: 'bad_jwt', message: 'jwt is required' };
    }
  }

  const client = new DynamicEvmWalletClient({ environmentId: ENVIRONMENT_ID });
  await client.authenticateJwt(authJwt);

  // Fetch full wallet metadata (incl. externalServerKeySharesBackupInfo, the
  // per-share pointers the MPC relay needs). The backend normally passes the
  // full walletMetadata (built from the Dynamic users REST endpoint); fall back
  // to the SDK's getWallets() lookup when it isn't provided.
  let walletMetadata = (md && typeof md === 'object')
    ? { chainName: 'EVM', thresholdSignatureScheme: 'TWO_OF_TWO', ...md, walletId, accountAddress }
    : {
        walletId,
        accountAddress,
        chainName: 'EVM',
        thresholdSignatureScheme: 'TWO_OF_TWO',
      };
  if (!walletMetadata.externalServerKeySharesBackupInfo) {
    try {
      const wallets = await client.getWallets();
      const match = (wallets || []).find(
        (w) => w && (w.walletId === walletId || (w.accountAddress || '').toLowerCase() === accountAddress.toLowerCase())
      );
      if (match && match.externalServerKeySharesBackupInfo) {
        walletMetadata = { ...match, accountAddress, chainName: 'EVM' };
      }
    } catch (e) {
      // fall through; signTransaction will raise if metadata is insufficient
    }
  }

  const [nonce, gasPrice, balance] = await Promise.all([
    publicClient.getTransactionCount({ address: accountAddress }),
    publicClient.getGasPrice(),
    publicClient.getBalance({ address: accountAddress }),
  ]);

  // 21000 for plain transfers; ERC-20 transfer costs ~50k. Estimate when calldata present.
  let gasLimit = 21000n;
  if (txData !== '0x') {
    gasLimit = await publicClient.estimateGas({
      account: accountAddress,
      to,
      value,
      data: txData,
    });
    gasLimit = (gasLimit * 120n) / 100n; // 20% headroom
  }
  const gasCost = gasLimit * gasPrice;
  const need = value + gasCost;
  if (!allowInsufficientFunds && balance < need) {
    throw {
      status: 402, code: 'insufficient_funds',
      message: `wallet balance ${balance} wei < needed ${need} wei (value + gas)`,
    };
  }

  const transaction = {
    chainId: CHAIN_ID,
    to,
    value,
    data: txData,
    nonce,
    gas: gasLimit,
    gasPrice,
  };

  const signedTransaction = await client.signTransaction({ walletMetadata, transaction });
  const txHash = keccak256(signedTransaction);
  return {
    signedTransaction,
    txHash,
    nonce: Number(nonce),
    gasLimit: gasLimit.toString(),
    gasPrice: gasPrice.toString(),
    chainId: CHAIN_ID,
  };
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'GET' && req.url === '/health') {
      return send(res, 200, { ok: true, chainId: CHAIN_ID });
    }
    if (req.method === 'POST' && req.url === '/sign') {
      const auth = req.headers.authorization || '';
      const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
      if (!timingSafeEqual(token, SIDECAR_TOKEN)) {
        return send(res, 401, { ok: false, code: 'unauthorized', message: 'bad sidecar token' });
      }
      let body;
      try {
        body = JSON.parse(await readBody(req));
      } catch {
        return send(res, 400, { ok: false, code: 'bad_json', message: 'invalid JSON body' });
      }
      try {
        const result = await handleSign(body);
        return send(res, 200, { ok: true, ...result });
      } catch (e) {
        const status = e.status || 500;
        return send(res, status, { ok: false, code: e.code || 'sign_failed', message: e.message || String(e) });
      }
    }
    return send(res, 404, { ok: false, code: 'not_found' });
  } catch (e) {
    return send(res, 500, { ok: false, code: 'internal', message: String(e && e.message || e) });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`dynamic_signer listening on ${HOST}:${PORT} (chain ${CHAIN_ID})`);
});

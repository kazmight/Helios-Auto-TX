const chalk = require("chalk");
const { ethers } = require("ethers");
const dotenv = require("dotenv");
const axios = require("axios");
const { v4: uuidv4 } = require("uuid"); // Note: v4 as uuidv4 for named export
const readline = require("readline");

// Load environment variables from .env file
dotenv.config();

// --- Configuration ---
const RPC_URL = "https://testnet1.helioschainlabs.org/";
const EXPLORER_TX_URL = "https://explorer.helioschainlabs.org/tx/"; // Helios Testnet Explorer URL
const TOKEN_ADDRESS = "0xD4949664cD82660AaE99bEdc034a0deA8A0bd517";
const BRIDGE_ROUTER_ADDRESS = "0x0000000000000000000000000000000000000900";
const STAKE_ROUTER_ADDRESS = "0x0000000000000000000000000000000000000800";
const CHAIN_ID = 42000;

// dailyActivityConfig will be set by user input
let dailyActivityConfig = {
  bridgeRepetitions: 0,
  minHlsBridge: 0,
  maxHlsBridge: 0,
  stakeRepetitions: 0,
  minHlsStake: 0,
  maxHlsStake: 0,
  minDelayBetweenTx: 30000,
  maxDelayBetweenTx: 60000,
  delayBetweenAccounts: 10000,
};
// --- End Configuration ---

// --- Password Definition (Moved to middle of script) ---
const SCRIPT_PASSWORD = "helios321";
// --- End Password Definition ---

const availableChains = [11155111, 43113, 97, 80002];
const chainNames = {
  11155111: "Ethereum Sepolia",
  43113: "Avalanche Fuji",
  97: "Binance Smart Chain",
  80002: "Polygon Amoy",
};

const availableValidators = [
  { name: "helios-hedge", address: "0x007a1123a54cdd9ba35ad2012db086b9d8350a5f" },
  { name: "helios-supra", address: "0x882f8a95409c127f0de7ba83b4dfa0096c3d8d79" },
  { name: "helios-peer", address: "0x72a9B3509B19D9Dbc2E0Df71c4A6451e8a3DD705" },
  { name: "helios-unity", address: "0x7e62c5e7Eba41fC8c25e605749C476C0236e0604" },
  { name: "helios-inter", address: "0xa75a393FF3D17eA7D9c9105d5459769EA3EAEf8D" },
];

const isDebug = false; // Set to true for detailed debug logs

let walletInfo = {
  address: "N/A",
  balanceHLS: "0.0000",
  activeAccount: "N/A",
};
let activityRunning = false;
let isCycleRunning = false;
let shouldStop = false;
let dailyActivityInterval = null;
let privateKeys = [];
let selectedWalletIndex = 0;
let nonceTracker = {};
let hasLoggedSleepInterrupt = false;
let activeProcesses = 0;

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: true // Important for cursor control
});

// Custom color and log functions
const colors = {
  reset: "\x1b[0m",
  bright: "\x1b[1m",
  dim: "\x1b[2m",
  underscore: "\x1b[4m",
  blink: "\x1b[5m",
  reverse: "\x1b[7m",
  hidden: "\x1b[8m",

  black: "\x1b[30m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
  white: "\x1b[37m",
  gray: "\x1b[90m",
};

const log = {
  info: (msg) => console.log(`${colors.green}[📣] ${msg}${colors.reset}`),
  warn: (msg) => console.log(`${colors.yellow}[⛔] ${msg}${colors.reset}`),
  error: (msg) => console.log(`${colors.red}[❎] ${msg}${colors.reset}`),
  success: (msg) => console.log(`${colors.green}[✅] ${msg}${colors.reset}`),
  loading: (msg) => console.log(`${colors.cyan}[⌛] ${msg}${colors.reset}`),
  step: (msg) => console.log(`${colors.white}[🔄] ${msg}${colors.reset}`),
  userInfo: (msg) => console.log(`${colors.white}[📌] ${msg}${colors.reset}`),
  debug: (msg) => {
    // Debug log only if isDebug is true
    if (isDebug) console.log(`${colors.blue}[🐛] ${msg}${colors.reset}`);
  },
};

// --- Console UI Functions (Moved to top for definition order) ---

function displayHeader() {
  console.clear();
console.log(chalk.bold.cyan("██╗░░██╗███████╗██╗░░░░░██╗░█████╗░░██████╗"));
console.log(chalk.bold.cyan("██║░░██║██╔════╝██║░░░░░██║██╔══██╗██╔════╝"));
console.log(chalk.bold.cyan("███████║█████╗░░██║░░░░░██║██║░░██║╚█████╗░"));
console.log(chalk.bold.cyan("██╔══██║██╔══╝░░██║░░░░░██║██║░░██║░╚═══██╗"));
console.log(chalk.bold.cyan("██║░░██║███████╗███████╗██║╚█████╔╝██████╔╝"));
console.log(chalk.bold.cyan("╚═╝░░╚═╝╚══════╝╚══════╝╚═╝░╚════╝░╚═════╝░"));
console.log(chalk.bold.cyan("           Script Author: Kazmight     "));
console.log(chalk.bold.cyan("    Join Telegram Channel Dasar Pemulung    ")); 
  console.log("");
}

function displayStatus() {
  const status = activityRunning
    ? chalk.yellowBright("Running Daily Activity...")
    : isCycleRunning && dailyActivityInterval !== null
    ? chalk.yellowBright("Waiting for next daily cycle...")
    : chalk.green("Idle");

  console.log(chalk.magenta(`Total Accounts: ${privateKeys.length}`));
  console.log(chalk.magenta(`Configured Bridge: ${dailyActivityConfig.bridgeRepetitions}`));
  console.log(chalk.magenta(`Configured Stake ${dailyActivityConfig.stakeRepetitions}`));
  console.log(
    chalk.magenta(
      `Delay between transactions: ${dailyActivityConfig.minDelayBetweenTx / 1000}s - ${
        dailyActivityConfig.maxDelayBetweenTx / 1000
      }s`
    )
  );
  console.log(chalk.magenta(`Delay between accounts: ${dailyActivityConfig.delayBetweenAccounts / 1000}s`));
  console.log("");
}

async function displayWalletInfo() {
  log.info("Fetching wallet information...");

  for (let i = 0; i < privateKeys.length; i++) {
    try {
      const provider = getProvider();
      const wallet = new ethers.Wallet(privateKeys[i], provider);
      const tokenContract = new ethers.Contract(TOKEN_ADDRESS, ["function balanceOf(address) view returns (uint256)"], provider);
      const hlsBalance = await tokenContract.balanceOf(wallet.address);
      const formattedHLS = Number(ethers.formatUnits(hlsBalance, 18)).toFixed(4);

      log.userInfo(`Address: ${chalk.magentaBright(getShortAddress(wallet.address))} HLS Balance: ${chalk.cyanBright(formattedHLS)}`);
    } catch (error) {
      log.error(`Address: ${chalk.redBright("N/A")} HLS Balance: ${chalk.redBright("0.0000")} (Error: ${error.message})`);
    }
  }
  console.log("");
}

// SIMPLIFIED askQuestion function
function askQuestion(query, hideInput = false) {
  return new Promise(resolve => {
    if (hideInput) {
      // Temporarily hide cursor for hidden input
      rl.write('\x1B[?25l'); // Hide cursor
      let buffer = '';
      const handleKeyPress = (char, key) => {
        if (key && key.name === 'return') {
          rl.off('line', handleKeyPress); // Remove listener
          rl.write('\n\x1B[?25h'); // Newline and show cursor
          resolve(buffer);
        } else if (key && key.name === 'backspace') {
          if (buffer.length > 0) {
            buffer = buffer.slice(0, -1);
          }
        } else if (char) {
          buffer += char;
        }
      };
      rl.input.on('keypress', handleKeyPress);
      rl.question(chalk.yellowBright(query), () => {}); // Keep readline active but don't use its input
    } else {
      rl.write('\x1B[?25h'); // Ensure cursor is visible for normal input
      rl.question(chalk.yellowBright(query), resolve);
    }
  });
}

async function promptForConfig() {
  console.clear();
  displayHeader();
  console.log(chalk.bold.cyan("--- Set Transaction Activity ---"));

  let bridgeReps = await askQuestion("Enter Bridge Transaction (e.g., 1-5): ");
  dailyActivityConfig.bridgeRepetitions = parseInt(bridgeReps) || 0;
  if (isNaN(dailyActivityConfig.bridgeRepetitions) || dailyActivityConfig.bridgeRepetitions < 0)
    dailyActivityConfig.bridgeRepetitions = 0;

  let minBridge = await askQuestion("Enter Min HLS for Bridge (e.g., 0.001): ");
  dailyActivityConfig.minHlsBridge = parseFloat(minBridge) || 0;
  if (isNaN(dailyActivityConfig.minHlsBridge) || dailyActivityConfig.minHlsBridge < 0) dailyActivityConfig.minHlsBridge = 0;

  let maxBridge = await askQuestion("Enter Max HLS for Bridge (e.g., 0.005): ");
  dailyActivityConfig.maxHlsBridge = parseFloat(maxBridge) || 0;
  if (isNaN(dailyActivityConfig.maxHlsBridge) || dailyActivityConfig.maxHlsBridge < dailyActivityConfig.minHlsBridge)
    dailyActivityConfig.maxHlsBridge = dailyActivityConfig.minHlsBridge;

  let stakeReps = await askQuestion("Enter Stake Transaction (e.g., 1-5): ");
  dailyActivityConfig.stakeRepetitions = parseInt(stakeReps) || 0;
  if (isNaN(dailyActivityConfig.stakeRepetitions) || dailyActivityConfig.stakeRepetitions < 0)
    dailyActivityConfig.stakeRepetitions = 0;

  let minStake = await askQuestion("Enter Min HLS for Stake (e.g., 0.001): ");
  dailyActivityConfig.minHlsStake = parseFloat(minStake) || 0;
  if (isNaN(dailyActivityConfig.minHlsStake) || dailyActivityConfig.minHlsStake < 0) dailyActivityConfig.minHlsStake = 0;

  let maxStake = await askQuestion("Enter Max HLS for Stake (e.g., 0.005): ");
  dailyActivityConfig.maxHlsStake = parseFloat(maxStake) || 0;
  if (isNaN(dailyActivityConfig.maxHlsStake) || dailyActivityConfig.maxHlsStake < dailyActivityConfig.minHlsStake)
    dailyActivityConfig.maxHlsStake = dailyActivityConfig.minHlsStake;

  let minDelay = await askQuestion("Enter Min Delay between transactions in seconds (e.g., 20): ");
  dailyActivityConfig.minDelayBetweenTx = (parseInt(minDelay) || 30) * 1000;
  if (isNaN(dailyActivityConfig.minDelayBetweenTx) || dailyActivityConfig.minDelayBetweenTx < 0)
    dailyActivityConfig.minDelayBetweenTx = 30000;

  let maxDelay = await askQuestion("Enter Max Delay between transactions in seconds (e.g., 40): ");
  dailyActivityConfig.maxDelayBetweenTx = (parseInt(maxDelay) || 60) * 1000;
  if (isNaN(dailyActivityConfig.maxDelayBetweenTx) || dailyActivityConfig.maxDelayBetweenTx < dailyActivityConfig.minDelayBetweenTx)
    dailyActivityConfig.maxDelayBetweenTx = dailyActivityConfig.minDelayBetweenTx + 30000;

  let accountDelay = await askQuestion("Enter Delay between accounts in seconds (e.g., 60): ");
  dailyActivityConfig.delayBetweenAccounts = (parseInt(accountDelay) || 10) * 1000;
  if (isNaN(dailyActivityConfig.delayBetweenAccounts) || dailyActivityConfig.delayBetweenAccounts < 0)
    dailyActivityConfig.delayBetweenAccounts = 10000;

  console.log(chalk.bold.cyan("\n--- Transaction Summary ---"));
  displayStatus();
  console.log(chalk.bold.cyan("Starting activity..."));
  await sleep(3000);
}

// --- Core Logic Functions ---

async function makeJsonRpcCall(method, params) {
  try {
    const id = uuidv4();
    const response = await axios.post(
      RPC_URL,
      {
        jsonrpc: "2.0",
        id,
        method,
        params,
      },
      {
        headers: { "Content-Type": "application/json" },
      }
    );
    const data = response.data;
    if (data.error) {
      throw new Error(`RPC Error: ${data.error.message} (code: ${data.error.code})`);
    }
    if (!data.result && data.result !== "") {
      throw new Error("No result in RPC response");
    }
    return data.result;
  } catch (error) {
    const errorMessage = error.response ? `HTTP ${error.response.status}: ${error.message}` : error.message;
    log.error(`JSON-RPC call failed (${method}): ${errorMessage}`);
    throw error;
  }
}

process.on("unhandledRejection", (reason, promise) => {
  log.error(`Unhandled Rejection at: ${promise}, reason: ${reason.message || reason}`);
});

process.on("uncaughtException", (error) => {
  log.error(`Uncaught Exception: ${error.message}\n${error.stack}`);
  process.exit(1);
});

function getShortAddress(address) {
  return address ? address.slice(0, 6) + "..." + address.slice(-4) : "N/A";
}

function getShortHash(hash) {
  return hash.slice(0, 6) + "..." + hash.slice(-4);
}

function loadPrivateKeys() {
  const keys = process.env.PRIVATE_KEYS;
  if (!keys) {
    log.error("PRIVATE_KEYS not found in .env file. Please ensure it's set.");
    privateKeys = [];
    return;
  }
  privateKeys = keys
    .split(",")
    .map((key) => key.trim())
    .filter((key) => key.match(/^(0x)?[0-9a-fA-F]{64}$/));

  if (privateKeys.length === 0) {
    log.error("No valid private keys found in .env PRIVATE_KEYS. Please check your .env file.");
  } else {
    log.success(`Loaded ${privateKeys.length} private keys from .env`);
  }
}

function getProvider(maxRetries = 3) {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const provider = new ethers.JsonRpcProvider(
        RPC_URL,
        { chainId: CHAIN_ID, name: "Helios" },
        {}
      );
      provider
        .getNetwork()
        .then((network) => {
          if (Number(network.chainId) !== CHAIN_ID) {
            throw new Error(`Network chain ID mismatch: expected ${CHAIN_ID}, got ${network.chainId}`);
          }
        })
        .catch((err) => {
          throw err;
        });
      return provider;
    } catch (error) {
      log.error(`Attempt ${attempt}/${maxRetries} failed to initialize provider: ${error.message}`);
      if (attempt < maxRetries) sleep(1000);
    }
  }
  log.error(`Failed to get provider after ${maxRetries} retries.`);
  throw new Error("Failed to get provider");
}

async function sleep(ms) {
  if (shouldStop) {
    if (!hasLoggedSleepInterrupt) {
      log.info("Process stopped successfully.");
      hasLoggedSleepInterrupt = true;
    }
    return;
  }
  activeProcesses++;
  try {
    await new Promise((resolve) => {
      const timeout = setTimeout(() => {
        resolve();
      }, ms);
      const checkStop = setInterval(() => {
        if (shouldStop) {
          clearTimeout(timeout);
          clearInterval(checkStop);
          if (!hasLoggedSleepInterrupt) {
            log.info("Process interrupted.");
          }
          resolve();
        }
      }, 100);
    });
  } catch (error) {
    log.error(`Sleep error: ${error.message}`);
  } finally {
    activeProcesses = Math.max(0, activeProcesses - 1);
  }
}

async function getNextNonce(provider, walletAddress) {
  if (shouldStop) {
    log.info("Nonce fetch stopped due to stop request.");
    throw new Error("Process stopped");
  }
  if (!walletAddress || !ethers.isAddress(walletAddress)) {
    log.error(`Invalid wallet address: ${walletAddress}`);
    throw new Error("Invalid wallet address");
  }
  try {
    const pendingNonce = await provider.getTransactionCount(walletAddress, "pending");
    const lastUsedNonce = nonceTracker[walletAddress] || pendingNonce - 1;
    const nextNonce = Math.max(pendingNonce, lastUsedNonce + 1);
    nonceTracker[walletAddress] = nextNonce;
    log.debug(`Fetched nonce ${nextNonce} for ${getShortAddress(walletAddress)}`);
    return nextNonce;
  } catch (error) {
    log.error(`Failed to fetch nonce for ${getShortAddress(walletAddress)}: ${error.message}`);
    throw error;
  }
}

async function bridge(wallet, amount, recipient, destChainId) {
  try {
    if (!wallet.address || !ethers.isAddress(wallet.address)) {
      throw new Error(`Invalid wallet address: ${wallet.address}`);
    }
    log.debug(`Building bridge transaction for amount ${amount} HLS to ${getShortAddress(wallet.address)}`);
    const chainIdHex = ethers.toBeHex(destChainId).slice(2).padStart(64, "0");
    const offset = "00000000000000000000000000000000000000000000000000000000000000a0";
    const token = TOKEN_ADDRESS.toLowerCase().slice(2).padStart(64, "0");
    log.debug(`Converting amount ${amount} to wei`);
    const amountWei = ethers.parseUnits(amount.toString(), 18);
    log.debug(`amountWei: ${amountWei.toString()}`);

    let amountHexRaw;
    try {
      amountHexRaw = ethers.toBeHex(amountWei);
      log.debug(`amountHexRaw: ${amountHexRaw}`);
    } catch (error) {
      log.error(`Failed to convert amountWei to hex: ${error.message}`);
      throw new Error(`Hex conversion failed: ${error.message}`);
    }

    let amountHex;
    try {
      amountHex = ethers.zeroPadValue(amountHexRaw, 32).slice(2);
      log.debug(`amountHex padded: ${amountHex}`);
    } catch (error) {
      log.error(`Failed to pad amountHex: ${error.message}`);
      throw new Error(`Hex padding failed: ${error.message}`);
    }

    const gasParam = ethers.toBeHex(ethers.parseUnits("1", "gwei")).slice(2).padStart(64, "0");
    log.debug(`Encoding recipient ${recipient} as string`);
    const recipientString = `0x${recipient.toLowerCase().slice(2)}`;
    const recipientLength = ethers.toBeHex(recipientString.length).slice(2).padStart(64, "0");
    const recipientPadded = Buffer.from(recipientString).toString("hex").padEnd(64, "0");

    const inputData =
      "0x7ae4a8ff" + chainIdHex + offset + token + amountHex + gasParam + recipientLength + recipientPadded;
    log.debug(`inputData: ${inputData}`);

    const tokenAbi = [
      "function allowance(address,address) view returns (uint256)",
      "function approve(address,uint256) returns (bool)",
    ];
    const tokenContract = new ethers.Contract(TOKEN_ADDRESS, tokenAbi, wallet);
    const allowance = await tokenContract.allowance(wallet.address, BRIDGE_ROUTER_ADDRESS);
    log.debug(`Allowance: ${allowance.toString()}`);
    if (allowance < amountWei) {
      log.info(`Approving router to spend ${amount} HLS`);
      const approveTx = await tokenContract.approve(BRIDGE_ROUTER_ADDRESS, amountWei);
      await approveTx.wait();
      log.success("Approval successful");
    }

    const tx = {
      to: BRIDGE_ROUTER_ADDRESS,
      data: inputData,
      gasLimit: 1500000,
      chainId: CHAIN_ID,
      nonce: await getNextNonce(wallet.provider, wallet.address),
    };
    log.debug(`Transaction object: ${JSON.stringify(tx)}`);

    const sentTx = await wallet.sendTransaction(tx);
    log.success(`Bridge transaction sent: ${getShortHash(sentTx.hash)}`);
    const receipt = await sentTx.wait();

    if (receipt.status === 0) {
      log.error(`Bridge transaction reverted: ${JSON.stringify(receipt)}`);
      throw new Error("Transaction reverted");
    }

    try {
      const historyResult = await makeJsonRpcCall("eth_getHyperionAccountTransferTxsByPageAndSize", [
        wallet.address,
        "0x1",
        "0xa",
      ]);
      log.debug(`Hyperion history result: ${JSON.stringify(historyResult)}`);
    } catch (rpcError) {
      log.error(`Failed to sync with portal via JSON-RPC: ${rpcError.message}`);
    }

    log.success("Bridge Transaction Confirmed And Synced With Portal");
    log.userInfo(`Transaction Link: ${chalk.blue(EXPLORER_TX_URL + receipt.hash)}`);
  } catch (error) {
    log.error(`Bridge operation failed: ${error.message}`);
    if (error.reason) {
      log.error(`Revert reason: ${error.reason}`);
    }
    if (error.receipt) {
      log.debug(`Transaction receipt: ${JSON.stringify(error.receipt)}`);
      log.error(`Failed Tx Hash: ${error.receipt.hash}`);
    }
    throw error;
  }
}

async function stake(wallet, amount, validatorAddress, validatorName) {
  try {
    if (!wallet.address || !ethers.isAddress(wallet.address)) {
      throw new Error(`Invalid wallet address: ${wallet.address}`);
    }
    log.debug(`Building stake transaction for amount ${amount} HLS to validator ${validatorName || validatorAddress}`);

    const fixedBytes = "ahelios";
    const abiCoder = ethers.AbiCoder.defaultAbiCoder();
    const encodedData = abiCoder.encode(
      ["address", "address", "uint256", "bytes"],
      [wallet.address, validatorAddress, ethers.parseUnits(amount.toString(), 18), ethers.toUtf8Bytes(fixedBytes)]
    );
    const inputData = "0xf5e56040" + encodedData.slice(2);

    const tx = {
      to: STAKE_ROUTER_ADDRESS,
      data: inputData,
      gasLimit: 1500000,
      chainId: CHAIN_ID,
      nonce: await getNextNonce(wallet.provider, wallet.address),
    };
    log.debug(`Stake transaction object: ${JSON.stringify(tx)}`);
    const sentTx = await wallet.sendTransaction(tx);
    log.success(`Stake transaction sent: ${getShortHash(sentTx.hash)}`);
    const receipt = await sentTx.wait();
    if (receipt.status === 0) {
      log.error(`Stake transaction reverted: ${JSON.stringify(receipt)}`);
      throw new Error("Transaction reverted");
    }

    try {
      const historyResult = await makeJsonRpcCall("eth_getAccountLastTransactionsInfo", [wallet.address]);
      log.debug(`Last transactions info: ${JSON.stringify(historyResult)}`);
    } catch (rpcError) {
      log.error(`Failed to sync with portal via JSON-RPC: ${rpcError.message}`);
    }

    log.success("Stake Transaction Confirmed And Synced With Portal");
    log.userInfo(`Transaction Link: ${chalk.blue(EXPLORER_TX_URL + receipt.hash)}`);
  } catch (error) {
    log.error(`Stake operation failed: ${error.message}`);
    if (error.reason) {
      log.error(`Revert reason: ${error.reason}`);
    }
    if (error.receipt) {
      log.debug(`Transaction receipt: ${JSON.stringify(error.receipt)}`);
      log.error(`Failed Tx Hash: ${error.receipt.hash}`);
    }
    throw error;
  }
}

async function runDailyActivity() {
  if (privateKeys.length === 0) {
    log.error("No valid private keys found. Please add them to PRIVATE_KEYS in your .env file.");
    return;
  }
  log.info(`Starting activity for all accounts`);
  log.info(`Bridge: ${dailyActivityConfig.bridgeRepetitions}`);
  log.info(`Stake: ${dailyActivityConfig.stakeRepetitions}`);
  log.info(
    `Delay between transactions: ${dailyActivityConfig.minDelayBetweenTx / 1000}s - ${
      dailyActivityConfig.maxDelayBetweenTx / 1000
    }s`
  );
  log.info(`Delay between accounts: ${dailyActivityConfig.delayBetweenAccounts / 1000}s`);

  activityRunning = true;
  isCycleRunning = true;
  shouldStop = false;
  hasLoggedSleepInterrupt = false;
  activeProcesses = Math.max(0, activeProcesses);

  try {
    for (let accountIndex = 0; accountIndex < privateKeys.length && !shouldStop; accountIndex++) {
      log.info(`Starting processing for account ${accountIndex + 1}`);
      selectedWalletIndex = accountIndex;
      let provider;
      try {
        provider = await getProvider();
        await provider.getNetwork();
      } catch (error) {
        log.error(`Failed to connect to provider for account ${accountIndex + 1}: ${error.message}`);
        continue;
      }
      const wallet = new ethers.Wallet(privateKeys[accountIndex], provider);
      if (!ethers.isAddress(wallet.address)) {
        log.error(`Invalid wallet address for account ${accountIndex + 1}: ${wallet.address}`);
        continue;
      }
      log.loading(`Processing account ${accountIndex + 1}: ${getShortAddress(wallet.address)}`);

      const shuffledChains = [...availableChains].sort(() => Math.random() - 0.5);

      for (
        let bridgeCount = 0;
        bridgeCount < dailyActivityConfig.bridgeRepetitions && !shouldStop;
        bridgeCount++
      ) {
        const destChainId = shuffledChains[bridgeCount % shuffledChains.length];
        const destChainName = chainNames[destChainId] || "Unknown";
        const amountHLS = (
          Math.random() * (dailyActivityConfig.maxHlsBridge - dailyActivityConfig.minHlsBridge) +
          dailyActivityConfig.minHlsBridge
        ).toFixed(4);
        const amountWei = ethers.parseUnits(amountHLS, 18);
        try {
          const nativeBalance = await provider.getBalance(wallet.address);
          const tokenContract = new ethers.Contract(
            TOKEN_ADDRESS,
            ["function balanceOf(address) view returns (uint256)"],
            provider
          );
          const hlsBalance = await tokenContract.balanceOf(wallet.address);
          log.loading(
            `Account ${accountIndex + 1} - Bridge ${bridgeCount + 1}: HLS Balance: ${ethers.formatUnits(
              hlsBalance,
              18
            )}`
          );
          log.info(
            `Account ${accountIndex + 1} - Bridge ${bridgeCount + 1}: Bridge ${amountHLS} HLS Helios ➯ ${destChainName}`
          );
          let gasPrice = (await provider.getFeeData()).maxFeePerGas;
          if (!gasPrice) {
            gasPrice = ethers.parseUnits("1", "gwei");
            log.info(`Using default gas price: 1 gwei`);
          }
          const gasLimit = BigInt(1500000);
          const gasCost = gasPrice * gasLimit;
          if (nativeBalance < gasCost) {
            log.error(
              `Account ${accountIndex + 1} - Bridge ${
                bridgeCount + 1
              }: Insufficient native balance (${ethers.formatEther(nativeBalance)} HLS)`
            );
            continue;
          }
          if (hlsBalance < amountWei) {
            log.error(
              `Account ${accountIndex + 1} - Bridge ${
                bridgeCount + 1
              }: Insufficient HLS balance (${ethers.formatUnits(hlsBalance, 18)} HLS)`
            );
            continue;
          }

          await bridge(wallet, amountHLS, wallet.address, destChainId);
        } catch (error) {
          log.error(`Account ${accountIndex + 1} - Bridge ${bridgeCount + 1}: Failed: ${error.message}`);
        }

        if (bridgeCount < dailyActivityConfig.bridgeRepetitions - 1 && !shouldStop) {
          const randomDelay =
            Math.floor(Math.random() * (dailyActivityConfig.maxDelayBetweenTx - dailyActivityConfig.minDelayBetweenTx + 1)) +
            dailyActivityConfig.minDelayBetweenTx;
          log.info(
            `Account ${accountIndex + 1} - Waiting ${Math.floor(randomDelay / 1000)} seconds before next bridge...`
          );
          await sleep(randomDelay);
        }
      }

      if (!shouldStop) {
        const stakeDelay =
          Math.floor(Math.random() * (dailyActivityConfig.maxDelayBetweenTx - dailyActivityConfig.minDelayBetweenTx + 1)) +
          dailyActivityConfig.minDelayBetweenTx;
        log.loading(`Waiting ${stakeDelay / 1000} seconds before staking...`);
        await sleep(stakeDelay);
      }

      const shuffledValidators = [...availableValidators].sort(() => Math.random() - 0.5);

      for (
        let stakeCount = 0;
        stakeCount < dailyActivityConfig.stakeRepetitions && !shouldStop;
        stakeCount++
      ) {
        const validator = shuffledValidators[stakeCount % shuffledValidators.length];
        const amountHLS = (
          Math.random() * (dailyActivityConfig.maxHlsStake - dailyActivityConfig.minHlsStake) +
          dailyActivityConfig.minHlsStake
        ).toFixed(4);
        try {
          log.info(`Account ${accountIndex + 1} - Stake ${stakeCount + 1}: Stake ${amountHLS} HLS to ${validator.name}`);
          await stake(wallet, amountHLS, validator.address, validator.name);
        } catch (error) {
          log.error(`Account ${accountIndex + 1} - Stake ${stakeCount + 1}: Failed: ${error.message}`);
        }

        if (stakeCount < dailyActivityConfig.stakeRepetitions - 1 && !shouldStop) {
          const randomDelay =
            Math.floor(Math.random() * (dailyActivityConfig.maxDelayBetweenTx - dailyActivityConfig.minDelayBetweenTx + 1)) +
            dailyActivityConfig.minDelayBetweenTx;
          log.info(
            `Account ${accountIndex + 1} - Waiting ${Math.floor(randomDelay / 1000)} seconds before next stake...`
          );
          await sleep(randomDelay);
        }
      }

      if (accountIndex < privateKeys.length - 1 && !shouldStop) {
        log.info(`Waiting ${dailyActivityConfig.delayBetweenAccounts / 1000} seconds before next account...`);
        await sleep(dailyActivityConfig.delayBetweenAccounts);
      }
    }
    if (!shouldStop && activeProcesses <= 0) {
      log.success("All accounts processed. Waiting 24 hours for next cycle.");
      dailyActivityInterval = setTimeout(runDailyActivity, 24 * 60 * 60 * 1000);
    }
  } catch (error) {
    log.error(`Daily activity failed: ${error.message}`);
  } finally {
    try {
      if (shouldStop) {
        const stopCheckInterval = setInterval(() => {
          if (activeProcesses <= 0) {
            clearInterval(stopCheckInterval);
            if (dailyActivityInterval) {
              clearTimeout(dailyActivityInterval);
              dailyActivityInterval = null;
              log.info("Cleared daily activity interval.");
            }
            activityRunning = false;
            isCycleRunning = false;
            shouldStop = false;
            hasLoggedSleepInterrupt = false;
            activeProcesses = 0;
            log.success("Daily activity stopped successfully.");
            console.log(chalk.bold.red("Script execution finished or stopped. Exiting..."));
            rl.close();
            process.exit(0);
          } else {
            log.info(`Waiting for ${activeProcesses} process to complete...`);
          }
        }, 1000);
      } else {
        activityRunning = false;
        isCycleRunning = activeProcesses > 0 || dailyActivityInterval !== null;
      }
      nonceTracker = {};
    } catch (finalError) {
      log.error(`Error in runDailyActivity cleanup: ${finalError.message}`);
    }
  }
}

// --- Initialization ---

async function initialize() {
  displayHeader(); // Display header early

  let passwordCorrect = false;
  while (!passwordCorrect) {
    const enteredPassword = (await askQuestion("Masukkan password untuk menjalankan bot: ", true)) // 'true' for hidden input
                               .replace(/[^a-zA-Z0-9]/g, '') // Only allow alphanumeric characters
                               .trim(); // Ensure no leading/trailing spaces

    if (enteredPassword === SCRIPT_PASSWORD) {
      log.success("Password benar! Memulai bot...");
      passwordCorrect = true;
    } else {
      log.error("Password salah. Silakan coba lagi.");
    }
  }

  loadPrivateKeys();
  await displayWalletInfo();

  await promptForConfig();

  log.info("Starting auto daily activity...");
  runDailyActivity();
}

initialize();

process.on("SIGINT", () => {
  log.warn("\nCtrl+C detected! Attempting to stop activity gracefully...");
  shouldStop = true;
  if (dailyActivityInterval) {
    clearTimeout(dailyActivityInterval);
    dailyActivityInterval = null;
    log.info("Daily activity interval cleared.");
  }
  setTimeout(() => {
    if (activeProcesses <= 0) {
      log.error("No active processes. Exiting now.");
      rl.close();
      process.exit(0);
    } else {
      log.warn(`Waiting for ${activeProcesses} remaining process(es) to finish...`);
    }
  }, 1000);
});

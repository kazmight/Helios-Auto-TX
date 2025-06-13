import chalk from "chalk";
import { ethers } from "ethers";
import dotenv from "dotenv";
import axios from "axios";
import { v4 as uuidv4 } from "uuid";
import readline from "readline"; // Import readline for console input

// Load environment variables from .env file
dotenv.config();

const RPC_URL = "https://testnet1.helioschainlabs.org/";
const TOKEN_ADDRESS = "0xD4949664cD82660AaE99bEdc034a0deA8A0bd517";
const BRIDGE_ROUTER_ADDRESS = "0x0000000000000000000000000000000000000900";
const STAKE_ROUTER_ADDRESS = "0x0000000000000000000000000000000000000800";
const CHAIN_ID = 42000;
const availableChains = [11155111, 43113, 97, 80002];
const chainNames = {
  11155111: "Sepolia",
  43113: "Fuji",
  97: "BSC Testnet",
  80002: "Amoy",
};

const availableValidators = [
  { name: "helios-hedge", address: "0x007a1123a54cdd9ba35ad2012db086b9d8350a5f" },
  { name: "helios-supra", address: "0x882f8a95409c127f0de7ba83b4dfa0096c3d8d79" },
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

let dailyActivityConfig = {
  bridgeRepetitions: Number(process.env.BRIDGE_REPETITIONS) || 1,
  minHlsBridge: Number(process.env.MIN_HLS_BRIDGE) || 0.001,
  maxHlsBridge: Number(process.env.MAX_HLS_BRIDGE) || 0.004,
  stakeRepetitions: Number(process.env.STAKE_REPETITIONS) || 1,
  minHlsStake: Number(process.env.MIN_HLS_STAKE) || 0.01,
  maxHlsStake: Number(process.env.MAX_HLS_STAKE) || 0.03,
};

// Interface for reading user input
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

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
    const errorMessage = error.response
      ? `HTTP ${error.response.status}: ${error.message}`
      : error.message;
    addLog(`JSON-RPC call failed (${method}): ${errorMessage}`, "error");
    throw error;
  }
}

process.on("unhandledRejection", (reason, promise) => {
  addLog(`Unhandled Rejection at: ${promise}, reason: ${reason.message || reason}`, "error");
});

process.on("uncaughtException", (error) => {
  addLog(`Uncaught Exception: ${error.message}\n${error.stack}`, "error");
  process.exit(1);
});

function getShortAddress(address) {
  return address ? address.slice(0, 6) + "..." + address.slice(-4) : "N/A";
}

function addLog(message, type = "info") {
  const timestamp = new Date().toLocaleTimeString("id-ID", { timeZone: "Asia/Jakarta" });
  let coloredMessage;
  switch (type) {
    case "error":
      coloredMessage = chalk.redBright(message);
      break;
    case "success":
      coloredMessage = chalk.greenBright(message);
      break;
    case "wait":
      coloredMessage = chalk.yellowBright(message);
      break;
    case "info":
      coloredMessage = chalk.whiteBright(message);
      break;
    case "delay":
      coloredMessage = chalk.cyanBright(message);
      break;
    case "debug":
      if (!isDebug) return; // Only log debug messages if isDebug is true
      coloredMessage = chalk.blueBright(message);
      break;
    default:
      coloredMessage = chalk.white(message);
  }
  console.log(`[${timestamp}] ${coloredMessage}`);
}

function getShortHash(hash) {
  return hash.slice(0, 6) + "..." + hash.slice(-4);
}

function loadPrivateKeys() {
  try {
    const keys = process.env.PRIVATE_KEYS;
    if (!keys) {
      throw new Error("PRIVATE_KEYS not found in .env file.");
    }
    privateKeys = keys
      .split(",")
      .map((key) => key.trim())
      .filter((key) => key.match(/^(0x)?[0-9a-fA-F]{64}$/));
    if (privateKeys.length === 0) throw new Error("No valid private keys in .env PRIVATE_KEYS");
    addLog(`Loaded ${privateKeys.length} private keys from .env`, "success");
  } catch (error) {
    addLog(`Failed to load private keys: ${error.message}`, "error");
    privateKeys = [];
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
      addLog(`Attempt ${attempt}/${maxRetries} failed to initialize provider: ${error.message}`, "error");
      if (attempt < maxRetries) sleep(1000);
    }
  }
  addLog(`Failed to get provider after ${maxRetries} retries.`, "error");
  throw new Error("Failed to get provider");
}

async function sleep(ms) {
  if (shouldStop) {
    if (!hasLoggedSleepInterrupt) {
      addLog("Process stopped successfully.", "info");
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
            addLog("Process interrupted.", "info");
            hasLoggedSleepInterrupt = true;
          }
          resolve();
        }
      }, 100);
    });
  } catch (error) {
    addLog(`Sleep error: ${error.message}`, "error");
  } finally {
    activeProcesses = Math.max(0, activeProcesses - 1);
  }
}

async function getNextNonce(provider, walletAddress) {
  if (shouldStop) {
    addLog("Nonce fetch stopped due to stop request.", "info");
    throw new Error("Process stopped");
  }
  if (!walletAddress || !ethers.isAddress(walletAddress)) {
    addLog(`Invalid wallet address: ${walletAddress}`, "error");
    throw new Error("Invalid wallet address");
  }
  try {
    const pendingNonce = await provider.getTransactionCount(walletAddress, "pending");
    const lastUsedNonce = nonceTracker[walletAddress] || pendingNonce - 1;
    const nextNonce = Math.max(pendingNonce, lastUsedNonce + 1);
    nonceTracker[walletAddress] = nextNonce;
    addLog(`Debug: Fetched nonce ${nextNonce} for ${getShortAddress(walletAddress)}`, "debug");
    return nextNonce;
  } catch (error) {
    addLog(`Failed to fetch nonce for ${getShortAddress(walletAddress)}: ${error.message}`, "error");
    throw error;
  }
}

async function bridge(wallet, amount, recipient, destChainId) {
  try {
    if (!wallet.address || !ethers.isAddress(wallet.address)) {
      throw new Error(`Invalid wallet address: ${wallet.address}`);
    }
    addLog(`Debug: Building bridge transaction for amount ${amount} HLS to ${getShortAddress(wallet.address)}`, "debug");
    const chainIdHex = ethers.toBeHex(destChainId).slice(2).padStart(64, "0");
    const offset = "00000000000000000000000000000000000000000000000000000000000000a0";
    const token = TOKEN_ADDRESS.toLowerCase().slice(2).padStart(64, "0");
    addLog(`Debug: Converting amount ${amount} to wei`, "debug");
    const amountWei = ethers.parseUnits(amount.toString(), 18);
    addLog(`Debug: amountWei: ${amountWei.toString()}`, "debug");

    let amountHexRaw;
    try {
      amountHexRaw = ethers.toBeHex(amountWei);
      addLog(`Debug: amountHexRaw: ${amountHexRaw}`, "debug");
    } catch (error) {
      addLog(`Debug: Failed to convert amountWei to hex: ${error.message}`, "error");
      throw new Error(`Hex conversion failed: ${error.message}`);
    }

    let amountHex;
    try {
      amountHex = ethers.zeroPadValue(amountHexRaw, 32).slice(2);
      addLog(`Debug: amountHex padded: ${amountHex}`, "debug");
    } catch (error) {
      addLog(`Debug: Failed to pad amountHex: ${error.message}`, "error");
      throw new Error(`Hex padding failed: ${error.message}`);
    }

    const gasParam = ethers.toBeHex(ethers.parseUnits("1", "gwei")).slice(2).padStart(64, "0");
    addLog(`Debug: Encoding recipient ${recipient} as string`, "debug");
    const recipientString = `0x${recipient.toLowerCase().slice(2)}`;
    const recipientLength = ethers.toBeHex(recipientString.length).slice(2).padStart(64, "0");
    const recipientPadded = Buffer.from(recipientString).toString("hex").padEnd(64, "0");

    const inputData =
      "0x7ae4a8ff" +
      chainIdHex +
      offset +
      token +
      amountHex +
      gasParam +
      recipientLength +
      recipientPadded;
    addLog(`Debug: inputData: ${inputData}`, "debug");

    const tokenAbi = [
      "function allowance(address,address) view returns (uint256)",
      "function approve(address,uint256) returns (bool)",
    ];
    const tokenContract = new ethers.Contract(TOKEN_ADDRESS, tokenAbi, wallet);
    const allowance = await tokenContract.allowance(wallet.address, BRIDGE_ROUTER_ADDRESS);
    addLog(`Debug: Allowance: ${allowance.toString()}`, "debug");
    if (allowance < amountWei) {
      addLog(`Approving router to spend ${amount} HLS`, "info");
      const approveTx = await tokenContract.approve(BRIDGE_ROUTER_ADDRESS, amountWei);
      await approveTx.wait();
      addLog("Approval successful", "success");
    }

    const tx = {
      to: BRIDGE_ROUTER_ADDRESS,
      data: inputData,
      gasLimit: 1500000,
      chainId: CHAIN_ID,
      nonce: await getNextNonce(wallet.provider, wallet.address),
    };
    addLog(`Debug: Transaction object: ${JSON.stringify(tx)}`, "debug");

    const sentTx = await wallet.sendTransaction(tx);
    addLog(`Bridge transaction sent: ${getShortHash(sentTx.hash)}`, "success");
    const receipt = await sentTx.wait();

    if (receipt.status === 0) {
      addLog(`Bridge transaction reverted: ${JSON.stringify(receipt)}`, "error");
      throw new Error("Transaction reverted");
    }

    try {
      const historyResult = await makeJsonRpcCall("eth_getHyperionAccountTransferTxsByPageAndSize", [
        wallet.address,
        "0x1",
        "0xa",
      ]);
      addLog(`Debug: Hyperion history result: ${JSON.stringify(historyResult)}`, "debug");
    } catch (rpcError) {
      addLog(`Failed to sync with portal via JSON-RPC: ${rpcError.message}`, "error");
    }

    addLog("Bridge Transaction Confirmed And Synced With Portal", "success");
  } catch (error) {
    addLog(`Bridge operation failed: ${error.message}`, "error");
    if (error.reason) {
      addLog(`Revert reason: ${error.reason}`, "error");
    }
    if (error.receipt) {
      addLog(`Transaction receipt: ${JSON.stringify(error.receipt)}`, "debug");
    }
    throw error;
  }
}

async function stake(wallet, amount, validatorAddress, validatorName) {
  try {
    if (!wallet.address || !ethers.isAddress(wallet.address)) {
      throw new Error(`Invalid wallet address: ${wallet.address}`);
    }
    addLog(
      `Debug: Building stake transaction for amount ${amount} HLS to validator ${
        validatorName || validatorAddress
      }`,
      "debug"
    );

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
    addLog(`Debug: Stake transaction object: ${JSON.stringify(tx)}`, "debug");
    const sentTx = await wallet.sendTransaction(tx);
    addLog(`Stake transaction sent: ${getShortHash(sentTx.hash)}`, "success");
    const receipt = await sentTx.wait();
    if (receipt.status === 0) {
      addLog(`Stake transaction reverted: ${JSON.stringify(receipt)}`, "error");
      throw new Error("Transaction reverted");
    }

    try {
      const historyResult = await makeJsonRpcCall("eth_getAccountLastTransactionsInfo", [wallet.address]);
      addLog(`Debug: Last transactions info: ${JSON.stringify(historyResult)}`, "debug");
    } catch (rpcError) {
      addLog(`Failed to sync with portal via JSON-RPC: ${rpcError.message}`, "error");
    }

    addLog("Stake Transaction Confirmed And Synced With Portal", "success");
  } catch (error) {
    addLog(`Stake operation failed: ${error.message}`, "error");
    if (error.reason) {
      addLog(`Revert reason: ${error.reason}`, "error");
    }
    if (error.receipt) {
      addLog(`Transaction receipt: ${JSON.stringify(error.receipt)}`, "debug");
    }
    throw error;
  }
}

async function runDailyActivity() {
  if (privateKeys.length === 0) {
    addLog("No valid private keys found.", "error");
    return;
  }
  addLog(
    `Starting daily activity for all accounts. Auto Bridge: ${dailyActivityConfig.bridgeRepetitions}x, Auto Stake: ${dailyActivityConfig.stakeRepetitions}x`,
    "info"
  );
  activityRunning = true;
  isCycleRunning = true;
  shouldStop = false;
  hasLoggedSleepInterrupt = false;
  activeProcesses = Math.max(0, activeProcesses);
  // No updateMenu() call here as there's no TUI menu

  try {
    for (let accountIndex = 0; accountIndex < privateKeys.length && !shouldStop; accountIndex++) {
      addLog(`Starting processing for account ${accountIndex + 1}`, "info");
      selectedWalletIndex = accountIndex; // Keep track for wallet info
      let provider;
      addLog(`Account ${accountIndex + 1}: Connecting without proxy`, "info");
      try {
        provider = await getProvider();
        await provider.getNetwork();
      } catch (error) {
        addLog(`Failed to connect to provider for account ${accountIndex + 1}: ${error.message}`, "error");
        continue;
      }
      const wallet = new ethers.Wallet(privateKeys[accountIndex], provider);
      if (!ethers.isAddress(wallet.address)) {
        addLog(`Invalid wallet address for account ${accountIndex + 1}: ${wallet.address}`, "error");
        continue;
      }
      addLog(`Processing account ${accountIndex + 1}: ${getShortAddress(wallet.address)}`, "wait");

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
          addLog(
            `Account ${accountIndex + 1} - Bridge ${bridgeCount + 1}: HLS Balance: ${ethers.formatUnits(
              hlsBalance,
              18
            )}`,
            "wait"
          );
          addLog(
            `Account ${accountIndex + 1} - Bridge ${bridgeCount + 1}: Bridge ${amountHLS} HLS Helios ➯  ${destChainName}`,
            "info"
          );
          let gasPrice = (await provider.getFeeData()).maxFeePerGas;
          if (!gasPrice) {
            gasPrice = ethers.parseUnits("1", "gwei");
            addLog(`Using default gas price: 1 gwei`, "info");
          }
          const gasLimit = BigInt(1500000);
          const gasCost = gasPrice * gasLimit;
          if (nativeBalance < gasCost) {
            addLog(
              `Account ${accountIndex + 1} - Bridge ${
                bridgeCount + 1
              }: Insufficient native balance (${ethers.formatEther(nativeBalance)} HLS)`,
              "error"
            );
            continue;
          }
          if (hlsBalance < amountWei) {
            addLog(
              `Account ${accountIndex + 1} - Bridge ${
                bridgeCount + 1
              }: Insufficient HLS balance (${ethers.formatUnits(hlsBalance, 18)} HLS)`,
              "error"
            );
            continue;
          }

          await bridge(wallet, amountHLS, wallet.address, destChainId);
          // No updateWallets() call here as there's no live TUI display
        } catch (error) {
          addLog(`Account ${accountIndex + 1} - Bridge ${bridgeCount + 1}: Failed: ${error.message}`, "error");
        }

        if (bridgeCount < dailyActivityConfig.bridgeRepetitions - 1 && !shouldStop) {
          const randomDelay = Math.floor(Math.random() * (60000 - 30000 + 1)) + 30000;
          addLog(
            `Account ${accountIndex + 1} - Waiting ${Math.floor(
              randomDelay / 1000
            )} seconds before next bridge...`,
            "delay"
          );
          await sleep(randomDelay);
        }
      }

      if (!shouldStop) {
        const stakeDelay = Math.floor(Math.random() * (15000 - 10000 + 1)) + 10000;
        addLog(`Waiting ${stakeDelay / 1000} seconds before staking...`, "wait");
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
          addLog(
            `Account ${accountIndex + 1} - Stake ${stakeCount + 1}: Stake ${amountHLS} HLS to ${validator.name}`,
            "info"
          );
          await stake(wallet, amountHLS, validator.address, validator.name);
          // No updateWallets() call here
        } catch (error) {
          addLog(`Account ${accountIndex + 1} - Stake ${stakeCount + 1}: Failed: ${error.message}`, "error");
        }

        if (stakeCount < dailyActivityConfig.stakeRepetitions - 1 && !shouldStop) {
          const randomDelay = Math.floor(Math.random() * (60000 - 30000 + 1)) + 30000;
          addLog(
            `Account ${accountIndex + 1} - Waiting ${Math.floor(
              randomDelay / 1000
            )} seconds before next stake...`,
            "delay"
          );
          await sleep(randomDelay);
        }
      }

      if (accountIndex < privateKeys.length - 1 && !shouldStop) {
        addLog(`Waiting 10 seconds before next account...`, "delay");
        await sleep(10000);
      }
    }
    if (!shouldStop && activeProcesses <= 0) {
      addLog("All accounts processed. Waiting 24 hours for next cycle.", "success");
      dailyActivityInterval = setTimeout(runDailyActivity, 24 * 60 * 60 * 1000);
    }
  } catch (error) {
    addLog(`Daily activity failed: ${error.message}`, "error");
  } finally {
    try {
      if (shouldStop) {
        const stopCheckInterval = setInterval(() => {
          if (activeProcesses <= 0) {
            clearInterval(stopCheckInterval);
            if (dailyActivityInterval) {
              clearTimeout(dailyActivityInterval);
              dailyActivityInterval = null;
              addLog("Cleared daily activity interval.", "info");
            }
            activityRunning = false;
            isCycleRunning = false;
            shouldStop = false;
            hasLoggedSleepInterrupt = false;
            activeProcesses = 0;
            addLog("Daily activity stopped successfully.", "success");
            // No updateMenu() or updateStatus() or safeRender() here
            displayMainMenu(); // Redisplay menu after stop
          } else {
            addLog(`Waiting for ${activeProcesses} process to complete...`, "info");
          }
        }, 1000);
      } else {
        activityRunning = false;
        isCycleRunning = activeProcesses > 0 || dailyActivityInterval !== null;
        // No updateMenu() or updateStatus() or safeRender() here
        displayMainMenu(); // Redisplay menu after cycle completion
      }
      nonceTracker = {}; // Reset nonce tracker after a full cycle or stop
    } catch (finalError) {
      addLog(`Error in runDailyActivity cleanup: ${finalError.message}`, "error");
    }
  }
}

// --- Console UI Functions ---

function displayHeader() {
  console.clear();
  console.log(chalk.bold.cyan("==================================="));
  console.log(chalk.bold.cyan("        HELIOS TESTNET AUTO BOT    "));
  console.log(chalk.bold.cyan("==================================="));
  console.log("");
}

function displayStatus() {
  const status = activityRunning
    ? chalk.yellowBright("Running Daily Activity...")
    : isCycleRunning && dailyActivityInterval !== null
    ? chalk.yellowBright("Waiting for next daily cycle...")
    : chalk.green("Idle");
  console.log(`Status: ${status}`);
  console.log(
    `Total Accounts: ${privateKeys.length} | Auto Bridge: ${dailyActivityConfig.bridgeRepetitions}x | Auto Stake: ${dailyActivityConfig.stakeRepetitions}x`
  );
  console.log("");
}

async function displayWalletInfo() {
  addLog("Fetching wallet information...", "info");
  const tokenAbi = ["function balanceOf(address) view returns (uint256)"];
  console.log(chalk.bold.blue("-------------------------------------------------"));
  console.log(chalk.bold.blue("  Address                   HLS Balance"));
  console.log(chalk.bold.blue("-------------------------------------------------"));
  for (let i = 0; i < privateKeys.length; i++) {
    try {
      const provider = getProvider();
      const wallet = new ethers.Wallet(privateKeys[i], provider);
      const tokenContract = new ethers.Contract(TOKEN_ADDRESS, tokenAbi, provider);
      const hlsBalance = await tokenContract.balanceOf(wallet.address);
      const formattedHLS = Number(ethers.formatUnits(hlsBalance, 18)).toFixed(4);
      console.log(
        `${chalk.magentaBright(getShortAddress(wallet.address))}       ${chalk.cyanBright(formattedHLS)}`
      );
    } catch (error) {
      console.log(`${chalk.redBright("N/A")}                       ${chalk.redBright("0.0000")} (Error: ${error.message})`);
    }
  }
  console.log(chalk.bold.blue("-------------------------------------------------"));
  console.log("");
}

function displayMainMenu() {
  displayHeader();
  displayStatus();
  console.log(chalk.bold.yellow("--- Main Menu ---"));
  console.log("1. Start Auto Daily Activity");
  console.log("2. Set Manual Config");
  console.log("3. Clear Console Output");
  console.log("4. Refresh Wallet Info");
  console.log("5. Exit");
  console.log(chalk.bold.yellow("-----------------"));
  promptMainAction();
}

function displayConfigMenu() {
  displayHeader();
  displayStatus();
  console.log(chalk.bold.yellow("--- Manual Config Options ---"));
  console.log("1. Set Bridge Repetitions (Current: " + dailyActivityConfig.bridgeRepetitions + ")");
  console.log(
    "2. Set HLS Range For Bridge (Current: " +
      dailyActivityConfig.minHlsBridge +
      " - " +
      dailyActivityConfig.maxHlsBridge +
      ")"
  );
  console.log("3. Set Stake Repetitions (Current: " + dailyActivityConfig.stakeRepetitions + ")");
  console.log(
    "4. Set HLS Range For Stake (Current: " +
      dailyActivityConfig.minHlsStake +
      " - " +
      dailyActivityConfig.maxHlsStake +
      ")"
  );
  console.log("5. Back to Main Menu");
  console.log(chalk.bold.yellow("-----------------------------"));
  promptConfigAction();
}

function promptMainAction() {
  rl.question(chalk.green("Choose an option: "), async (answer) => {
    switch (answer.trim()) {
      case "1":
        if (isCycleRunning) {
          addLog("Cycle is still running. Stop the current cycle first.", "error");
        } else {
          runDailyActivity();
        }
        break;
      case "2":
        displayConfigMenu();
        break;
      case "3":
        console.clear();
        addLog("Console output cleared.", "success");
        displayMainMenu();
        break;
      case "4":
        await displayWalletInfo();
        addLog("Wallet info refreshed.", "success");
        displayMainMenu();
        break;
      case "5":
        addLog("Exiting application", "info");
        rl.close();
        process.exit(0);
      default:
        addLog("Invalid option. Please try again.", "error");
        displayMainMenu();
        break;
    }
  });
}

function promptConfigAction() {
  rl.question(chalk.green("Choose an option for config: "), async (answer) => {
    switch (answer.trim()) {
      case "1":
        rl.question(
          chalk.cyan("Enter new Bridge Repetitions (current: " + dailyActivityConfig.bridgeRepetitions + "): "),
          (value) => {
            const numValue = parseInt(value.trim());
            if (isNaN(numValue) || numValue <= 0) {
              addLog("Invalid input. Please enter a positive number.", "error");
            } else {
              dailyActivityConfig.bridgeRepetitions = numValue;
              addLog(`Bridge Repetitions set to ${dailyActivityConfig.bridgeRepetitions}`, "success");
            }
            displayConfigMenu();
          }
        );
        break;
      case "2":
        rl.question(
          chalk.cyan(
            "Enter Min HLS for Bridge (current: " + dailyActivityConfig.minHlsBridge + "): "
          ),
          (minValue) => {
            rl.question(
              chalk.cyan(
                "Enter Max HLS for Bridge (current: " + dailyActivityConfig.maxHlsBridge + "): "
              ),
              (maxValue) => {
                const min = parseFloat(minValue.trim());
                const max = parseFloat(maxValue.trim());
                if (isNaN(min) || isNaN(max) || min <= 0 || max <= 0 || min > max) {
                  addLog("Invalid HLS range. Please enter positive numbers, and min <= max.", "error");
                } else {
                  dailyActivityConfig.minHlsBridge = min;
                  dailyActivityConfig.maxHlsBridge = max;
                  addLog(`HLS Range for Bridge set to ${min} - ${max}`, "success");
                }
                displayConfigMenu();
              }
            );
          }
        );
        break;
      case "3":
        rl.question(
          chalk.cyan("Enter new Stake Repetitions (current: " + dailyActivityConfig.stakeRepetitions + "): "),
          (value) => {
            const numValue = parseInt(value.trim());
            if (isNaN(numValue) || numValue <= 0) {
              addLog("Invalid input. Please enter a positive number.", "error");
            } else {
              dailyActivityConfig.stakeRepetitions = numValue;
              addLog(`Stake Repetitions set to ${dailyActivityConfig.stakeRepetitions}`, "success");
            }
            displayConfigMenu();
          }
        );
        break;
      case "4":
        rl.question(
          chalk.cyan(
            "Enter Min HLS for Stake (current: " + dailyActivityConfig.minHlsStake + "): "
          ),
          (minValue) => {
            rl.question(
              chalk.cyan(
                "Enter Max HLS for Stake (current: " + dailyActivityConfig.maxHlsStake + "): "
              ),
              (maxValue) => {
                const min = parseFloat(minValue.trim());
                const max = parseFloat(maxValue.trim());
                if (isNaN(min) || isNaN(max) || min <= 0 || max <= 0 || min > max) {
                  addLog("Invalid HLS range. Please enter positive numbers, and min <= max.", "error");
                } else {
                  dailyActivityConfig.minHlsStake = min;
                  dailyActivityConfig.maxHlsStake = max;
                  addLog(`HLS Range for Stake set to ${min} - ${max}`, "success");
                }
                displayConfigMenu();
              }
            );
          }
        );
        break;
      case "5":
        displayMainMenu();
        break;
      default:
        addLog("Invalid option. Please try again.", "error");
        displayConfigMenu();
        break;
    }
  });
}

async function initialize() {
  console.clear();
  displayHeader();
  loadPrivateKeys(); // Load keys from .env
  await displayWalletInfo(); // Display wallet info on startup
  displayMainMenu(); // Show the main menu
}

initialize();

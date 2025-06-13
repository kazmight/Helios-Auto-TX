# Helios Testnet Auto Transaction

This Node.js bot automates bridging and staking activities on the Helios Testnet using multiple private keys. It's designed to help interact with the network by performing repetitive tasks with configurable delays.

## Don't forget join telegram channel Dasar Pemulung for Password.
## Links telegram: https://t.me/dasarpemulung

## Features

* **Multi-Account Support:** Process transactions for multiple accounts loaded from a `.env` file.
* **Configurable Bridge Transactions:** Set the number of bridge repetitions and a range for HLS amounts to bridge to various testnet chains (Ethereum Sepolia, Avalanche Fuji, Binance Smart Chain, Polygon Amoy).
* **Configurable Stake Transactions:** Define the number of stake repetitions and a range for HLS amounts to stake on predefined validators.
* **Flexible Delays:** Customize delays between transactions and between processing different accounts to mimic human-like activity.
* **Secure Password Protection:** Requires a password to start the bot.
* **Detailed Logging:** Provides clear console output for activities, balances, and transaction statuses.
* **Graceful Shutdown:** Supports stopping the bot safely using `Ctrl+C`.

Getting Started
Follow these steps to set up and run the bot:

Prerequisites
Node.js: Make sure you have Node.js (v14 or higher recommended) installed. You can download it from nodejs.org.

## 1. Installation
Clone:
```Bash
git clone https://github.com/kazmight/Helios-Auto-TX.git
cd Helios-Auto-TX
```

## 2. Install Dependencies: Run the following command to install all required Node.js packages:
```Bash
npm install chalk ethers dotenv axios uuidv4 readline
```

## 3. Running the Bot Execute the Script: 
```Bash
node index.js
```
## Configuration

Before running the bot, you need to set up your environment variables and review the bot's internal configuration.

Environment Variables (`.env` file)

Open a file named **`.env`** in the root directory of your project. This file stores your private keys securely.

* Replace `YOUR_PRIVATE_KEY_X` with your actual Ethereum private keys.
* Separate multiple private keys with commas (e.g., `"key1,key2"`).
* **Keep your `.env` file private and never commit it to version control!**

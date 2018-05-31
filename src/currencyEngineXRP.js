/**
 * Created by paul on 7/7/17.
 */
// @flow

import { currencyInfo } from './currencyInfoXRP.js'
import type {
  EdgeCurrencyEngine,
  EdgeTransaction,
  EdgeCurrencyEngineCallbacks,
  EdgeCurrencyEngineOptions,
  EdgeSpendInfo,
  EdgeWalletInfo,
  EdgeMetaToken,
  EdgeCurrencyInfo,
  EdgeDenomination,
  EdgeFreshAddress,
  EdgeDataDump,
  EdgeCurrencyPlugin,
  EdgeIo
} from 'edge-core-js'
import { sprintf } from 'sprintf-js'
import { bns } from 'biggystring'
import { CustomTokenSchema, GetServerInfoSchema } from './xrpSchema.js'
import {
  DATA_STORE_FILE,
  DATA_STORE_FOLDER,
  WalletLocalData,
  type XrpCustomToken
} from './xrpTypes.js'
import { isHex, normalizeAddress, validateObject } from './utils.js'

const ADDRESS_POLL_MILLISECONDS = 3000
const BLOCKHEIGHT_POLL_MILLISECONDS = 15000
const SAVE_DATASTORE_MILLISECONDS = 10000
// const ADDRESS_QUERY_LOOKBACK_BLOCKS = '8' // ~ 2 minutes
const ADDRESS_QUERY_LOOKBACK_BLOCKS = (4 * 60 * 24 * 7) // ~ one week

const PRIMARY_CURRENCY = currencyInfo.currencyCode
const CHECK_UNCONFIRMED = true

type RippleParams = {
  publicAddress?: string,
  contractAddress?: string
}

class RippleEngine {
  walletInfo: EdgeWalletInfo
  edgeTxLibCallbacks: EdgeCurrencyEngineCallbacks
  walletLocalFolder: any
  rippleApi: Object
  engineOn: boolean
  addressesChecked: boolean
  tokenCheckStatus: { [currencyCode: string]: number } // Each currency code can be a 0-1 value
  walletLocalData: WalletLocalData
  walletLocalDataDirty: boolean
  transactionsChangedArray: Array<EdgeTransaction>
  currencyInfo: EdgeCurrencyInfo
  allTokens: Array<EdgeMetaToken>
  customTokens: Array<EdgeMetaToken>
  currentSettings: any
  timers: any
  walletId: string
  io: EdgeIo

  constructor (currencyPlugin: EdgeCurrencyPlugin, io_: any, walletInfo: EdgeWalletInfo, rippleApi: Object, opts: EdgeCurrencyEngineOptions) {
    // Validate that we are a valid EdgeCurrencyEngine:
    // eslint-disable-next-line no-unused-vars
    const test: EdgeCurrencyEngine = this

    const { walletLocalFolder, callbacks } = opts

    this.io = io_
    this.rippleApi = rippleApi
    this.engineOn = false
    this.addressesChecked = false
    this.tokenCheckStatus = {}
    this.walletLocalDataDirty = false
    this.transactionsChangedArray = []
    this.walletInfo = walletInfo
    this.walletId = walletInfo.id ? `${walletInfo.id} - ` : ''
    this.currencyInfo = currencyInfo
    this.allTokens = currencyInfo.metaTokens.slice(0)
    this.customTokens = []
    this.timers = {}

    if (typeof opts.optionalSettings !== 'undefined') {
      this.currentSettings = opts.optionalSettings
    } else {
      this.currentSettings = this.currencyInfo.defaultSettings
    }

    // Hard coded for testing
    // this.walletInfo.keys.rippleKey = '389b07b3466eed587d6bdae09a3613611de9add2635432d6cd1521af7bbc3757'
    // this.walletInfo.keys.rippleAddress = '0x9fa817e5A48DD1adcA7BEc59aa6E3B1F5C4BeA9a'
    this.edgeTxLibCallbacks = callbacks
    this.walletLocalFolder = walletLocalFolder

    if (typeof this.walletInfo.keys.rippleAddresss !== 'string') {
      if (walletInfo.keys.rippleAddress) {
        this.walletInfo.keys.rippleAddress = walletInfo.keys.rippleAddress
      } else {
        const pubKeys = currencyPlugin.derivePublicKey(this.walletInfo)
        this.walletInfo.keys.rippleAddress = pubKeys.rippleAddress
      }
    }
    this.log(`Created Wallet Type ${this.walletInfo.type} for Currency Plugin ${this.currencyInfo.pluginName} `)
  }

  // *************************************
  // Private methods
  // *************************************
  async fetchGetEtherscan (cmd: string) {
    let apiKey = ''
    if (global.etherscanApiKey && global.etherscanApiKey.length > 5) {
      apiKey = '&apikey=' + global.etherscanApiKey
    }
    const url = sprintf('%s/api%s%s', this.currentSettings.otherSettings.etherscanApiServers[0], cmd, apiKey)
    return this.fetchGet(url)
  }

  async fetchGet (url: string) {
    const response = await this.io.fetch(url, {
      method: 'GET'
    })
    if (!response.ok) {
      const cleanUrl = url.replace(global.etherscanApiKey, 'private')
      throw new Error(
        `The server returned error code ${response.status} for ${cleanUrl}`
      )
    }
    return response.json()
  }

  async fetchPostBlockcypher (cmd: string, body: any) {
    let apiKey = ''
    if (global.blockcypherApiKey && global.blockcypherApiKey.length > 5) {
      apiKey = '&token=' + global.blockcypherApiKey
    }
    const url = sprintf('%s/%s%s', this.currentSettings.otherSettings.blockcypherApiServers[0], cmd, apiKey)
    const response = await this.io.fetch(url, {
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json'
      },
      method: 'POST',
      body: JSON.stringify(body)
    })
    return response.json()
  }

  // *************************************
  // Poll on the blockheight
  // *************************************
  async blockHeightInnerLoop () {
    try {
      const jsonObj = await this.rippleApi.getServerInfo()
      const valid = validateObject(jsonObj, GetServerInfoSchema)
      if (valid) {
        const blockHeight: number = jsonObj.validatedLedger.ledgerVersion
        this.log(`Got block height ${blockHeight}`)
        if (this.walletLocalData.blockHeight !== blockHeight) {
          this.walletLocalData.blockHeight = blockHeight // Convert to decimal
          this.walletLocalDataDirty = true
          this.edgeTxLibCallbacks.onBlockHeightChanged(this.walletLocalData.blockHeight)
        }
      }
    } catch (err) {
      this.log('Error fetching height: ' + err)
    }
  }

  processEtherscanTransaction (tx: any) {
    let netNativeAmount:string // Amount received into wallet
    const ourReceiveAddresses:Array<string> = []

    const nativeNetworkFee:string = bns.mul(tx.gasPrice, tx.gasUsed)

    if (tx.from.toLowerCase() === this.walletLocalData.rippleAddress.toLowerCase()) {
      netNativeAmount = bns.sub('0', tx.value)

      // For spends, include the network fee in the transaction amount
      netNativeAmount = bns.sub(netNativeAmount, nativeNetworkFee)

      if (bns.gte(tx.nonce, this.walletLocalData.nextNonce)) {
        this.walletLocalData.nextNonce = bns.add(tx.nonce, '1')
      }
    } else {
      netNativeAmount = bns.add('0', tx.value)
      ourReceiveAddresses.push(this.walletLocalData.rippleAddress.toLowerCase())
    }

    const xrpParams: RippleParams = {}

    const edgeTransaction:EdgeTransaction = {
      txid: tx.hash,
      date: parseInt(tx.timeStamp),
      currencyCode: 'XRP',
      blockHeight: parseInt(tx.blockNumber),
      nativeAmount: netNativeAmount,
      networkFee: nativeNetworkFee,
      ourReceiveAddresses,
      signedTx: 'unsigned_right_now',
      otherParams: xrpParams
    }

    const idx = this.findTransaction(PRIMARY_CURRENCY, tx.hash)
    if (idx === -1) {
      this.log(sprintf('New transaction: %s', tx.hash))

      // New transaction not in database
      this.addTransaction(PRIMARY_CURRENCY, edgeTransaction)

      this.edgeTxLibCallbacks.onTransactionsChanged(
        this.transactionsChangedArray
      )
      this.transactionsChangedArray = []
    } else {
      // Already have this tx in the database. See if anything changed
      const transactionsArray = this.walletLocalData.transactionsObj[ PRIMARY_CURRENCY ]
      const edgeTx = transactionsArray[ idx ]

      if (
        edgeTx.blockHeight !== edgeTransaction.blockHeight ||
        edgeTx.networkFee !== edgeTransaction.networkFee ||
        edgeTx.nativeAmount !== edgeTransaction.nativeAmount ||
        edgeTx.otherParams.errorVal !== edgeTransaction.otherParams.errorVal
      ) {
        this.log(sprintf('Update transaction: %s height:%s', tx.hash, tx.blockNumber))
        this.updateTransaction(PRIMARY_CURRENCY, edgeTransaction, idx)
        this.edgeTxLibCallbacks.onTransactionsChanged(
          this.transactionsChangedArray
        )
        this.transactionsChangedArray = []
      } else {
        // this.log(sprintf('Old transaction. No Update: %s', tx.hash))
      }
    }
  }

  async checkAddressFetch (tk: string, url: string) {
    let checkAddressSuccess = true
    let jsonObj = {}
    let valid = false

    try {
      jsonObj = await this.fetchGetEtherscan(url)
      valid = validateObject(jsonObj, {
        'type': 'object',
        'properties': {
          'result': {'type': 'string'}
        },
        'required': ['result']
      })
      if (valid) {
        const balance = jsonObj.result

        if (typeof this.walletLocalData.totalBalances[tk] === 'undefined') {
          this.walletLocalData.totalBalances[tk] = '0'
        }
        if (!bns.eq(balance, this.walletLocalData.totalBalances[tk])) {
          this.walletLocalData.totalBalances[tk] = balance
          this.log(tk + ': token Address balance: ' + balance)
          this.edgeTxLibCallbacks.onBalanceChanged(tk, balance)
        }
      } else {
        checkAddressSuccess = false
      }
    } catch (e) {
      checkAddressSuccess = false
    }
    return checkAddressSuccess
  }

  async checkTransactionsFetch () {
    const address = this.walletLocalData.rippleAddress
    const endBlock:number = 999999999
    let startBlock:number = 0
    let checkAddressSuccess = true
    let url = ''
    let jsonObj = {}
    let valid = false
    if (this.walletLocalData.lastAddressQueryHeight > ADDRESS_QUERY_LOOKBACK_BLOCKS) {
      // Only query for transactions as far back as ADDRESS_QUERY_LOOKBACK_BLOCKS from the last time we queried transactions
      startBlock = this.walletLocalData.lastAddressQueryHeight - ADDRESS_QUERY_LOOKBACK_BLOCKS
    }

    try {
      url = sprintf('?module=account&action=txlist&address=%s&startblock=%d&endblock=%d&sort=asc', address, startBlock, endBlock)
      jsonObj = await this.fetchGetEtherscan(url)
      valid = validateObject(jsonObj, {
        'type': 'object',
        'properties': {
          'result': {
            'type': 'array',
            'items': {
              'type': 'object',
              'properties': {
                'blockNumber': {'type': 'string'},
                'timeStamp': {'type': 'string'},
                'hash': {'type': 'string'},
                'from': {'type': 'string'},
                'to': {'type': 'string'},
                'nonce': {'type': 'string'},
                'value': {'type': 'string'},
                'gas': {'type': 'string'},
                'gasPrice': {'type': 'string'},
                'cumulativeGasUsed': {'type': 'string'},
                'gasUsed': {'type': 'string'},
                'confirmations': {'type': 'string'}
              },
              'required': [
                'blockNumber',
                'timeStamp',
                'hash',
                'from',
                'to',
                'nonce',
                'value',
                'gas',
                'gasPrice',
                'cumulativeGasUsed',
                'gasUsed',
                'confirmations'
              ]
            }
          }
        },
        'required': ['result']
      })

      if (valid) {
        const transactions = jsonObj.result
        this.log('Fetched transactions count: ' + transactions.length)

        // Get transactions
        // Iterate over transactions in address
        for (let i = 0; i < transactions.length; i++) {
          const tx = transactions[i]
          this.processEtherscanTransaction(tx)
          this.tokenCheckStatus[ PRIMARY_CURRENCY ] = ((i + 1) / transactions.length)
          if (i % 10 === 0) {
            this.updateOnAddressesChecked()
          }
        }
        if (transactions.length === 0) {
          this.tokenCheckStatus[ PRIMARY_CURRENCY ] = 1
        }
        this.updateOnAddressesChecked()
      } else {
        checkAddressSuccess = false
      }
    } catch (e) {
      this.log(e)
      checkAddressSuccess = false
    }
    return checkAddressSuccess
  }

  updateOnAddressesChecked () {
    if (this.addressesChecked) {
      return
    }
    const activeTokens: Array<string> = []

    for (const tokenCode of this.walletLocalData.enabledTokens) {
      const ti = this.getTokenInfo(tokenCode)
      if (ti) {
        activeTokens.push(tokenCode)
      }
    }

    const perTokenSlice = 1 / activeTokens.length
    let numCompleteStatus = 0
    let totalStatus = 0
    for (const token of activeTokens) {
      const status = this.tokenCheckStatus[token]
      totalStatus += status * perTokenSlice
      if (status === 1) {
        numCompleteStatus++
      }
    }
    if (numCompleteStatus === activeTokens.length) {
      this.addressesChecked = true
      this.edgeTxLibCallbacks.onAddressesChecked(1)
      this.walletLocalData.lastAddressQueryHeight = this.walletLocalData.blockHeight
    } else {
      this.edgeTxLibCallbacks.onAddressesChecked(totalStatus)
    }
  }

  async checkUnconfirmedTransactionsFetch () {

  }

  // **********************************************
  // Check all addresses for new transactions
  // **********************************************
  async checkAddressesInnerLoop () {
    const address = this.walletLocalData.rippleAddress
    try {
      // Ripple only has one address
      let url = ''
      const promiseArray = []

      // ************************************
      // Fetch token balances
      // ************************************
      // https://api.etherscan.io/api?module=account&action=tokenbalance&contractaddress=0x57d90b64a1a57749b0f932f1a3395792e12e7055&address=0xe04f27eb70e025b78871a2ad7eabe85e61212761&tag=latest&apikey=YourApiKeyToken
      for (const tk of this.walletLocalData.enabledTokens) {
        if (tk === PRIMARY_CURRENCY) {
          url = sprintf('?module=account&action=balance&address=%s&tag=latest', address)
        } else {
          if (this.getTokenStatus(tk)) {
            const tokenInfo = this.getTokenInfo(tk)
            if (tokenInfo && typeof tokenInfo.contractAddress === 'string') {
              url = sprintf('?module=account&action=tokenbalance&contractaddress=%s&address=%s&tag=latest', tokenInfo.contractAddress, this.walletLocalData.rippleAddress)
              // promiseArray.push(this.checkTokenTransactionsFetch(tk))
            } else {
              continue
            }
          } else {
            continue
          }
        }
        promiseArray.push(this.checkAddressFetch(tk, url))
      }

      promiseArray.push(this.checkTransactionsFetch())
      if (CHECK_UNCONFIRMED) {
        promiseArray.push(this.checkUnconfirmedTransactionsFetch())
      }
      await Promise.all(promiseArray)
    } catch (e) {
      this.log('Error fetching address transactions: ' + address)
    }
  }

  findTransaction (currencyCode: string, txid: string) {
    if (typeof this.walletLocalData.transactionsObj[currencyCode] === 'undefined') {
      return -1
    }

    const currency = this.walletLocalData.transactionsObj[currencyCode]
    return currency.findIndex(element => {
      return normalizeAddress(element.txid) === normalizeAddress(txid)
    })
  }

  sortTxByDate (a: EdgeTransaction, b: EdgeTransaction) {
    return b.date - a.date
  }

  addTransaction (currencyCode: string, edgeTransaction: EdgeTransaction) {
    // Add or update tx in transactionsObj
    const idx = this.findTransaction(currencyCode, edgeTransaction.txid)

    if (idx === -1) {
      this.log('addTransaction: adding and sorting:' + edgeTransaction.txid)
      if (typeof this.walletLocalData.transactionsObj[currencyCode] === 'undefined') {
        this.walletLocalData.transactionsObj[currencyCode] = []
      }
      this.walletLocalData.transactionsObj[currencyCode].push(edgeTransaction)

      // Sort
      this.walletLocalData.transactionsObj[currencyCode].sort(this.sortTxByDate)
      this.walletLocalDataDirty = true
      this.transactionsChangedArray.push(edgeTransaction)
    } else {
      this.updateTransaction(currencyCode, edgeTransaction, idx)
    }
  }

  updateTransaction (currencyCode: string, edgeTransaction: EdgeTransaction, idx: number) {
    // Update the transaction
    this.walletLocalData.transactionsObj[currencyCode][idx] = edgeTransaction
    this.walletLocalDataDirty = true
    this.transactionsChangedArray.push(edgeTransaction)
    this.log('updateTransaction:' + edgeTransaction.txid)
  }

  // *************************************
  // Save the wallet data store
  // *************************************
  async saveWalletLoop () {
    if (this.walletLocalDataDirty) {
      try {
        this.log('walletLocalDataDirty. Saving...')
        const walletJson = JSON.stringify(this.walletLocalData)
        await this.walletLocalFolder
          .folder(DATA_STORE_FOLDER)
          .file(DATA_STORE_FILE)
          .setText(walletJson)
        this.walletLocalDataDirty = false
      } catch (err) {
        this.log(err)
      }
    }
  }

  doInitialCallbacks () {
    for (const currencyCode of this.walletLocalData.enabledTokens) {
      try {
        this.edgeTxLibCallbacks.onTransactionsChanged(
          this.walletLocalData.transactionsObj[currencyCode]
        )
        this.edgeTxLibCallbacks.onBalanceChanged(currencyCode, this.walletLocalData.totalBalances[currencyCode])
      } catch (e) {
        this.log('Error for currencyCode', currencyCode, e)
      }
    }
  }

  getTokenInfo (token: string) {
    return this.allTokens.find(element => {
      return element.currencyCode === token
    })
  }

  async addToLoop (func: string, timer: number) {
    try {
      // $FlowFixMe
      await this[func]()
    } catch (e) {
      this.log('Error in Loop:', func, e)
    }
    if (this.engineOn) {
      this.timers[func] = setTimeout(() => {
        if (this.engineOn) {
          this.addToLoop(func, timer)
        }
      }, timer)
    }
    return true
  }

  log (...text: Array<any>) {
    text[0] = `${this.walletId}${text[0]}`
    console.log(...text)
  }

  // *************************************
  // Public methods
  // *************************************

  updateSettings (settings: any) {
    this.currentSettings = settings
  }

  async startEngine () {
    this.engineOn = true
    this.doInitialCallbacks()
    await this.rippleApi.connect()
    this.addToLoop('blockHeightInnerLoop', BLOCKHEIGHT_POLL_MILLISECONDS)
    this.addToLoop('checkAddressesInnerLoop', ADDRESS_POLL_MILLISECONDS)
    this.addToLoop('saveWalletLoop', SAVE_DATASTORE_MILLISECONDS)
  }

  async killEngine () {
    // Set status flag to false
    this.engineOn = false
    // Clear Inner loops timers
    for (const timer in this.timers) {
      clearTimeout(this.timers[timer])
    }
    this.timers = {}
    await this.rippleApi.disconnect()
  }

  async resyncBlockchain (): Promise<void> {
    await this.killEngine()
    const temp = JSON.stringify({
      enabledTokens: this.walletLocalData.enabledTokens,
      rippleAddresss: this.walletLocalData.rippleAddress
    })
    this.walletLocalData = new WalletLocalData(temp)
    this.walletLocalDataDirty = true
    await this.saveWalletLoop()
    await this.startEngine()
  }

  // synchronous
  getBlockHeight (): number {
    return parseInt(this.walletLocalData.blockHeight)
  }

  enableTokensSync (tokens: Array<string>) {
    for (const token of tokens) {
      if (this.walletLocalData.enabledTokens.indexOf(token) === -1) {
        this.walletLocalData.enabledTokens.push(token)
      }
    }
  }

  // asynchronous
  async enableTokens (tokens: Array<string>) {
    this.enableTokensSync(tokens)
  }

  disableTokensSync (tokens: Array<string>) {
    for (const token of tokens) {
      const index = this.walletLocalData.enabledTokens.indexOf(token)
      if (index !== -1) {
        this.walletLocalData.enabledTokens.splice(index, 1)
      }
    }
  }

  // asynchronous
  async disableTokens (tokens: Array<string>) {
    this.disableTokensSync(tokens)
  }

  async getEnabledTokens (): Promise<Array<string>> {
    return this.walletLocalData.enabledTokens
  }

  async addCustomToken (tokenObj: any) {
    const valid = validateObject(tokenObj, CustomTokenSchema)

    if (valid) {
      const ethTokenObj: XrpCustomToken = tokenObj
      // If token is already in currencyInfo, error as it cannot be changed
      for (const tk of this.currencyInfo.metaTokens) {
        if (
          tk.currencyCode.toLowerCase() === ethTokenObj.currencyCode.toLowerCase() ||
          tk.currencyName.toLowerCase() === ethTokenObj.currencyName.toLowerCase()
        ) {
          throw new Error('ErrorCannotModifyToken')
        }
      }

      // Validate the token object
      if (ethTokenObj.currencyCode.toUpperCase() !== ethTokenObj.currencyCode) {
        throw new Error('ErrorInvalidCurrencyCode')
      }
      if (ethTokenObj.currencyCode.length < 2 || ethTokenObj.currencyCode.length > 7) {
        throw new Error('ErrorInvalidCurrencyCodeLength')
      }
      if (ethTokenObj.currencyName.length < 3 || ethTokenObj.currencyName.length > 20) {
        throw new Error('ErrorInvalidCurrencyNameLength')
      }
      if (bns.lt(ethTokenObj.multiplier, '1') || bns.gt(ethTokenObj.multiplier, '100000000000000000000000000000000')) {
        throw new Error('ErrorInvalidMultiplier')
      }
      let contractAddress = ethTokenObj.contractAddress.replace('0x', '').toLowerCase()
      if (!isHex(contractAddress) || contractAddress.length !== 40) {
        throw new Error('ErrorInvalidContractAddress')
      }
      contractAddress = '0x' + contractAddress

      for (const tk of this.customTokens) {
        if (
          tk.currencyCode.toLowerCase() === ethTokenObj.currencyCode.toLowerCase() ||
          tk.currencyName.toLowerCase() === ethTokenObj.currencyName.toLowerCase()
        ) {
          // Remove old token first then re-add it to incorporate any modifications
          const idx = this.customTokens.findIndex(element => element.currencyCode === ethTokenObj.currencyCode)
          if (idx !== -1) {
            this.customTokens.splice(idx, 1)
          }
        }
      }

      // Create a token object for inclusion in customTokens
      const denom: EdgeDenomination = {
        name: ethTokenObj.currencyCode,
        multiplier: ethTokenObj.multiplier
      }
      const edgeMetaToken: EdgeMetaToken = {
        currencyCode: ethTokenObj.currencyCode,
        currencyName: ethTokenObj.currencyName,
        denominations: [denom],
        contractAddress
      }

      this.customTokens.push(edgeMetaToken)
      this.allTokens = this.currencyInfo.metaTokens.concat(this.customTokens)
      this.enableTokensSync([edgeMetaToken.currencyCode])
    } else {
      throw new Error('Invalid custom token object')
    }
  }

  // synchronous
  getTokenStatus (token: string) {
    return this.walletLocalData.enabledTokens.indexOf(token) !== -1
  }

  // synchronous
  getBalance (options: any): string {
    let currencyCode = PRIMARY_CURRENCY

    if (typeof options !== 'undefined') {
      const valid = validateObject(options, {
        'type': 'object',
        'properties': {
          'currencyCode': {'type': 'string'}
        }
      })

      if (valid) {
        currencyCode = options.currencyCode
      }
    }

    if (typeof this.walletLocalData.totalBalances[currencyCode] === 'undefined') {
      return '0'
    } else {
      const nativeBalance = this.walletLocalData.totalBalances[currencyCode]
      return nativeBalance
    }
  }

  // synchronous
  getNumTransactions (options: any): number {
    let currencyCode = PRIMARY_CURRENCY

    const valid = validateObject(options, {
      'type': 'object',
      'properties': {
        'currencyCode': {'type': 'string'}
      }
    })

    if (valid) {
      currencyCode = options.currencyCode
    }

    if (typeof this.walletLocalData.transactionsObj[currencyCode] === 'undefined') {
      return 0
    } else {
      return this.walletLocalData.transactionsObj[currencyCode].length
    }
  }

  // asynchronous
  async getTransactions (options: any) {
    let currencyCode:string = PRIMARY_CURRENCY

    const valid:boolean = validateObject(options, {
      'type': 'object',
      'properties': {
        'currencyCode': {'type': 'string'}
      }
    })

    if (valid) {
      currencyCode = options.currencyCode
    }

    if (typeof this.walletLocalData.transactionsObj[currencyCode] === 'undefined') {
      return []
    }

    let startIndex:number = 0
    let numEntries:number = 0
    if (options === null) {
      return this.walletLocalData.transactionsObj[currencyCode].slice(0)
    }
    if (options.startIndex !== null && options.startIndex > 0) {
      startIndex = options.startIndex
      if (
        startIndex >=
        this.walletLocalData.transactionsObj[currencyCode].length
      ) {
        startIndex =
          this.walletLocalData.transactionsObj[currencyCode].length - 1
      }
    }
    if (options.numEntries !== null && options.numEntries > 0) {
      numEntries = options.numEntries
      if (
        numEntries + startIndex >
        this.walletLocalData.transactionsObj[currencyCode].length
      ) {
        // Don't read past the end of the transactionsObj
        numEntries =
          this.walletLocalData.transactionsObj[currencyCode].length -
          startIndex
      }
    }

    // Copy the appropriate entries from the arrayTransactions
    let returnArray = []

    if (numEntries) {
      returnArray = this.walletLocalData.transactionsObj[currencyCode].slice(
        startIndex,
        numEntries + startIndex
      )
    } else {
      returnArray = this.walletLocalData.transactionsObj[currencyCode].slice(
        startIndex
      )
    }
    return returnArray
  }

  // synchronous
  getFreshAddress (options: any): EdgeFreshAddress {
    return { publicAddress: this.walletLocalData.rippleAddress }
  }

  // synchronous
  addGapLimitAddresses (addresses: Array<string>, options: any) {
  }

  // synchronous
  isAddressUsed (address: string, options: any) {
    return false
  }

  // synchronous
  async makeSpend (edgeSpendInfo: EdgeSpendInfo) {
    // Validate the spendInfo
    const valid = validateObject(edgeSpendInfo, {
      'type': 'object',
      'properties': {
        'currencyCode': { 'type': 'string' },
        'networkFeeOption': { 'type': 'string' },
        'spendTargets': {
          'type': 'array',
          'items': {
            'type': 'object',
            'properties': {
              'currencyCode': { 'type': 'string' },
              'publicAddress': { 'type': 'string' },
              'nativeAmount': { 'type': 'string' },
              'destMetadata': { 'type': 'object' },
              'destWallet': { 'type': 'object' }
            },
            'required': [
              'publicAddress'
            ]
          }
        }
      },
      'required': [ 'spendTargets' ]
    })

    if (!valid) {
      throw (new Error('Error: invalid ABCSpendInfo'))
    }

    // Ripple can only have one output
    if (edgeSpendInfo.spendTargets.length !== 1) {
      throw (new Error('Error: only one output allowed'))
    }

    let tokenInfo = {}
    tokenInfo.contractAddress = ''

    let currencyCode:string = ''
    if (typeof edgeSpendInfo.currencyCode === 'string') {
      currencyCode = edgeSpendInfo.currencyCode
      if (!this.getTokenStatus(currencyCode)) {
        throw (new Error('Error: Token not supported or enabled'))
      } else if (currencyCode !== 'XRP') {
        tokenInfo = this.getTokenInfo(currencyCode)
        if (!tokenInfo || typeof tokenInfo.contractAddress !== 'string') {
          throw (new Error('Error: Token not supported or invalid contract address'))
        }
      }
    } else {
      currencyCode = 'XRP'
    }
    edgeSpendInfo.currencyCode = currencyCode

    // ******************************
    // Get the fee amount

    let xrpParams: RippleParams

    let publicAddress = ''
    if (typeof edgeSpendInfo.spendTargets[0].publicAddress === 'string') {
      publicAddress = edgeSpendInfo.spendTargets[0].publicAddress
    } else {
      throw new Error('No valid spendTarget')
    }

    if (currencyCode === PRIMARY_CURRENCY) {
      xrpParams = {
        publicAddress
      }
    } else {
      let contractAddress = ''
      if (typeof tokenInfo.contractAddress === 'string') {
        contractAddress = tokenInfo.contractAddress
      } else {
        throw new Error('makeSpend: Invalid contract address')
      }
      xrpParams = {
        publicAddress,
        contractAddress
      }
    }

    let nativeAmount = '0'
    if (typeof edgeSpendInfo.spendTargets[0].nativeAmount === 'string') {
      nativeAmount = edgeSpendInfo.spendTargets[0].nativeAmount
    } else {
      throw (new Error('Error: no amount specified'))
    }

    const InsufficientFundsError = new Error('Insufficient funds')
    InsufficientFundsError.name = 'ErrorInsufficientFunds'
    const InsufficientFundsXrpError = new Error('Insufficient XRP for transaction fee')
    InsufficientFundsXrpError.name = 'ErrorInsufficientFundsMoreEth'

    const balanceXrp = this.walletLocalData.totalBalances.XRP
    let nativeNetworkFee = '' // Todo: get fee
    let totalTxAmount = '0'
    let parentNetworkFee = null

    if (currencyCode === PRIMARY_CURRENCY) {
      totalTxAmount = bns.add(nativeNetworkFee, nativeAmount)
      if (bns.gt(totalTxAmount, balanceXrp)) {
        throw (InsufficientFundsError)
      }
      nativeAmount = bns.mul(totalTxAmount, '-1')
    } else {
      parentNetworkFee = nativeNetworkFee

      if (bns.gt(nativeNetworkFee, balanceXrp)) {
        throw (InsufficientFundsXrpError)
      }

      nativeNetworkFee = '0' // Do not show a fee for token transations.
      const balanceToken = this.walletLocalData.totalBalances[currencyCode]
      if (bns.gt(nativeAmount, balanceToken)) {
        throw (InsufficientFundsError)
      }
      nativeAmount = bns.mul(nativeAmount, '-1')
    }

    // const negativeOneBN = new BN('-1', 10)
    // nativeAmountBN.imul(negativeOneBN)
    // nativeAmount = nativeAmountBN.toString(10)

    // **********************************
    // Create the unsigned EdgeTransaction

    const edgeTransaction: EdgeTransaction = {
      txid: '', // txid
      date: 0, // date
      currencyCode, // currencyCode
      blockHeight: 0, // blockHeight
      nativeAmount, // nativeAmount
      networkFee: nativeNetworkFee, // networkFee
      ourReceiveAddresses: [], // ourReceiveAddresses
      signedTx: '0', // signedTx
      otherParams: xrpParams // otherParams
    }

    if (parentNetworkFee) {
      edgeTransaction.parentNetworkFee = parentNetworkFee
    }

    return edgeTransaction
  }

  // asynchronous
  async signTx (edgeTransaction: EdgeTransaction): Promise<EdgeTransaction> {
    // Do signing

    let nativeAmountHex

    // let nativeAmountHex = bns.mul('-1', edgeTransaction.nativeAmount, 16)
    if (edgeTransaction.currencyCode === PRIMARY_CURRENCY) {
      // Remove the networkFee from the nativeAmount
      const nativeAmount = bns.add(edgeTransaction.nativeAmount, edgeTransaction.networkFee)
      nativeAmountHex = bns.mul('-1', nativeAmount, 16)
    } else {
      nativeAmountHex = bns.mul('-1', edgeTransaction.nativeAmount, 16)
    }
    console.log(nativeAmountHex)
    // Todo: increment nonce and sign transaction

    edgeTransaction.signedTx = ''
    edgeTransaction.txid = ''
    edgeTransaction.date = Date.now() / 1000

    return edgeTransaction
  }

  // asynchronous
  async broadcastTx (edgeTransaction: EdgeTransaction): Promise<EdgeTransaction> {
    // Todo: broadcast
    return edgeTransaction
  }

  // asynchronous
  async saveTx (edgeTransaction: EdgeTransaction) {
    this.addTransaction(edgeTransaction.currencyCode, edgeTransaction)
    this.edgeTxLibCallbacks.onTransactionsChanged([edgeTransaction])
  }

  getDisplayPrivateSeed () {
    if (this.walletInfo.keys && this.walletInfo.keys.rippleKey) {
      return this.walletInfo.keys.rippleKey
    }
    return ''
  }

  getDisplayPublicSeed () {
    if (this.walletInfo.keys && this.walletInfo.keys.rippleAddresss) {
      return this.walletInfo.keys.rippleAddress
    }
    return ''
  }

  dumpData (): EdgeDataDump {
    const dataDump: EdgeDataDump = {
      walletId: this.walletId.split(' - ')[0],
      walletType: this.walletInfo.type,
      pluginType: this.currencyInfo.pluginName,
      data: {
        walletLocalData: this.walletLocalData
      }
    }
    return dataDump
  }
}

export { RippleEngine }

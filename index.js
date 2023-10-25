exports.name = 'Confluent_Decrypt';
exports.version = '0.1';
exports.group = 'Custom Functions';

const {NestedPropertyAccessor} = C.expr;
const { KeyClient,CryptographyClient,KnownEncryptionAlgorithms } = require("@azure/keyvault-keys");
const { ClientSecretCredential } = require("@azure/identity");
const cLogger = C.util.getLogger('func:confluentDecryptor');
const Promise = require('promise');
const {Buffer} = require('buffer');

let srcField = '_raw';
let dstField;
let keyField;// = '__headers["encryption/SymmetricKey/wrappingkey/dataencryptionkey"].data';
let decryptedData;
let keyVaultKey;
let CryptoClient;
let url;

const dataValue = 'This is a test';

let AZURE_TENANT_ID;
let AZURE_CLIENT_ID;
let AZURE_CLIENT_SECRET;
let keyVaultName;
let azureKeyName;
let credential;


const algorithm = KnownEncryptionAlgorithms.RSAOaep256;

exports.init = async (opts) => {
  const conf = opts.conf;
  keyVaultName = conf.keyVault;
  azureKeyName = conf.keyName;
  AZURE_CLIENT_ID = conf.clientID;
  AZURE_TENANT_ID = conf.tenantID;
  AZURE_CLIENT_SECRET = conf.textPassword;
  url = "https://" + keyVaultName + ".vault.azure.net";

  srcField = new NestedPropertyAccessor((conf.srcField || '_raw').trim());
  dstField = new NestedPropertyAccessor((conf.dstField || '_raw').trim());
  keyField = new NestedPropertyAccessor(conf.eventKeyField);


  credential = new ClientSecretCredential(
    AZURE_TENANT_ID,AZURE_CLIENT_ID,AZURE_CLIENT_SECRET
  );

  const client = await getAzureClient();
  cLogger.info('AzureClient', client)
  keyVaultKey = await getAzureKey(client);
  cLogger.info('keyVault', keyVaultKey)
  CryptoClient = await azureCryptoClient(keyVaultKey);
  cLogger.info('CryptoClient', CryptoClient)
};

function getAzureClient() {
  let authPromise = new Promise(function(resolve, reject) {
    let client = new KeyClient(url, credential)
    resolve(client);
  })
  return authPromise;
}

async function getAzureKey(client) {
  let keyPromise = new Promise(function(resolve, reject) {
    let keyVaultKey = client.getKey(azureKeyName);
    resolve(keyVaultKey);
  })
 return await keyPromise;
}
  
async function azureCryptoClient(keyVaultKey) {
  let encryptPromise = new Promise(function(resolve, reject) {
    let CryptoClient = new CryptographyClient(keyVaultKey, credential);
    resolve(CryptoClient);
  });
  return await encryptPromise;
}

async function azureEncrypt(CryptoClient) {
  let encryptResultPromise = new Promise(function(resolve, reject) {
    const encryptParams = {algorithm,plaintext: Buffer.from(dataValue)};
    let encryptResult = CryptoClient.encrypt(encryptParams);
    resolve(encryptResult);
  });
  return await encryptResultPromise;
}

async function azureDecrypt(CryptoClient, encryptResult) {
  let decryptPromise = new Promise(function(resolve, reject) {
    //let decryptResults = CryptoClient.decrypt(algorithm, encryptResult.result);
    let decryptResults = CryptoClient.decrypt(algorithm, encryptResult);
    resolve(decryptResults);
  }); 
  
  return await decryptPromise;
}

function setValue (value){
  cLogger.info('insideSetValue', value);
  decryptedData = value.toString('utf8');
  cLogger.info(decryptedData);  
 
}

exports.process = (event) => {
  let eventKeyData;
  let decryptEventKeyResults;
  let encryptedSrcData;
  let decryptEventClient;
  let decryptEventDataResults;
  let decBuffer;
  let decString;
  

    // Decrypting the event Key using the key vault key
    // Get key from keyfield specified in GUI
    eventKeyData = keyField.get(event);
    //Decrypt Eventkeydata field using the key vault key, 
    cLogger.info('eventKeyData',eventKeyData);
    decryptEventKeyResults = azureDecrypt(CryptoClient, eventKeyData);
    cLogger.info(decryptEventKeyResults);

  
    // //decrypt encrypted field using the event key
    // //get encrypted data from srcField specified in GUI
    encryptedSrcData = _raw.get(event);
    // //Create new crypto client using the event key decrypted above
    decryptEventClient = azureCryptoClient(decryptEventKeyResults);
    // //Decrypt encrypted field using the event Key
    decryptEventDataResults = azureDecrypt(decryptEventClient,encryptedSrcData)
    
    // // Add decrypted data to destField value
    decBuf = Buffer.from(decryptEventDataResults.result, 'base64')
    decString = decBuf.toString('utf8')
    dstField.set(event, decString)
 
  return event;
};

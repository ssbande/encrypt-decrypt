from helper import askDob, askMode, askRounds, askIv, askEncryptedString, generateTwelveBlockedData, getRoundKey, getXorValue
from dict import getDictionaryDataFromBinary, getS1ValueFor, getS2ValueFor, getBinaryStringFor, prependZeroes, getBinaryForDigit
from encryption import encryptData, encryptDataCtr

def getDecryptionInfo():
  	dob = askDob()
	totalRounds = askRounds()
	encryptedString = ''
	mode = askMode()

	iv = ''
	if(int(mode) > 1):
		iv = askIv()

	desEncData = ''
	cbcEncData = ''
	ofbEncData = ''
	ctrEncData = ''
	if(int(mode) == 5):
		desEncData = askEncryptedString('DES')
		cbcEncData = askEncryptedString('CBC')
		ofbEncData = askEncryptedString('OFB')
		ctrEncData = askEncryptedString('CTR')
	else:
		encryptedString = askEncryptedString()

	return {"dob": dob, "mode": mode, "totalRounds": totalRounds, "encData": encryptedString, "iv": iv, "desEncData": desEncData, "cbcEncData": cbcEncData, "ofbEncData": ofbEncData, "ctrEncData": ctrEncData}

def decryptWithSelectedMode(key, info):
  	try:
		if(int(info['mode']) == 1):
			return decryptData(key, info['encData'], info['totalRounds'])
		elif(int(info['mode']) == 2):
			return decryptDataCbc(key, info['encData'], info['totalRounds'], info['iv'])
		elif(int(info['mode']) == 3):
			return decryptDataOfb(key, info['encData'], info['totalRounds'], info['iv'])
		elif(int(info['mode']) == 4):
			return decryptDataCtr(key, info['encData'], info['totalRounds'], info['iv'])
		else:
			return {
				"des": decryptData(key, info['desEncData'], info['totalRounds']),
				"cbc": decryptDataCbc(key, info['cbcEncData'], info['totalRounds'], info['iv']),
				"ofb": decryptDataOfb(key, info['ofbEncData'], info['totalRounds'], info['iv']),
				"ctr": decryptDataCtr(key, info['ctrEncData'], info['totalRounds'], info['iv'])
			}
	except Exception as e:
		print(e)
		return False

def decryptData(key, encData, totalRounds):
	binaryBlocks = generateTwelveBlockedData(encData)
	allBlockResult = ''

	for block in binaryBlocks:
		l0 = block[:6]
		r0 = block[6:]
		blockRes = decryptDataForBlock(int(totalRounds)-1, totalRounds, key, l0, r0)
		allBlockResult += blockRes
	
	inputString = getDictionaryDataFromBinary(allBlockResult)
	return {"allBlockResult": allBlockResult, "inputString": inputString}

def decryptDataForBlock(currRound, totalRounds, key, left, right):
	edKey = getRoundKey(currRound, key)
	expRight = right[0:2] + right[3] + right[2] + right[3] + right[2] + right[4:]
	xorKeyxRight = getBinaryForDigit(getXorValue(edKey, expRight))
	xorKeyxRight = prependZeroes(xorKeyxRight, 8)
	nr = getS1ValueFor(xorKeyxRight[:4]) + getS2ValueFor(xorKeyxRight[4:])
	nextRight = getBinaryForDigit(getXorValue(left, nr))
	nextRight = prependZeroes(nextRight, 6)
	newNextRight = prependZeroes(getBinaryForDigit(getXorValue(left, nextRight)), 6)

	if(currRound > 0):
		return decryptDataForBlock(currRound-1, totalRounds, key, right, nextRight)
	elif(currRound == 0):
		return nextRight + right

def decryptDataCbc(key, encData, totalRounds, iv):
	binaryBlocks = generateTwelveBlockedData(encData)
	ivBinary = getBinaryStringFor(iv)
	allBlockResult = ''

	for block in binaryBlocks:
		blockRes = decryptDataForCbc(key, block, totalRounds, ivBinary)
		allBlockResult += blockRes
		ivBinary = block

	inputString = getDictionaryDataFromBinary(allBlockResult)
	return {"allBlockResult": allBlockResult, "inputString": inputString}

def decryptDataForCbc(key, block, totalRounds, iv):
	l0 = block[:6]
	r0 = block[6:]
	cipherDecryptResult = decryptDataForBlock(int(totalRounds)-1, totalRounds, key, l0, r0)
	xoredResult = getBinaryForDigit(getXorValue(iv, cipherDecryptResult))
	xoredResult = prependZeroes(xoredResult, 12)
	return xoredResult

def decryptDataOfb(key, encData, totalRounds, iv):
	binaryBlocks = generateTwelveBlockedData(encData)
	ivBinary = getBinaryStringFor(iv)
	allBlockResult = ''

	for block in binaryBlocks:
		blockRes = decryptDataForOfb(ivBinary, key, block, totalRounds)
		allBlockResult += blockRes['allBlockResult']
		ivBinary = blockRes['encValue']
	inputString = getDictionaryDataFromBinary(allBlockResult)
	return {"allBlockResult": allBlockResult, "inputString": inputString}

def decryptDataForOfb(iv, key, block, totalRounds):
	blockCipherResult = encryptData(key, iv, int(totalRounds))
	xoredResult = getBinaryForDigit(getXorValue(blockCipherResult, block))
	xoredResult = prependZeroes(xoredResult, 12)
	return {"allBlockResult": xoredResult, "encValue": blockCipherResult}

def decryptDataCtr(key, encData, totalRounds, iv):
	allBlockResult = encryptDataCtr(key, encData, int(totalRounds), iv)
	inputString = getDictionaryDataFromBinary(allBlockResult)
	return {"allBlockResult": allBlockResult, "inputString": inputString}



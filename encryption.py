from helper import askName, askStudentId, askDob, askMode, askRounds, askIv, generateTwelveBlockedData, getRoundKey, getXorValue
from dict import getDictionaryDataFromBinary, getS1ValueFor, getS2ValueFor, getBinaryStringFor, CHAR_FILL, prependZeroes, getBinaryForDigit

def getInfo():
  	name = askName()
	originalName = name
	nameLen = len(name)
	if(nameLen != 10):
		remainingDigits = (10 - nameLen)
		for x in range(0, remainingDigits):
			name = name + CHAR_FILL

	studentId = askStudentId()
	dob = askDob()
	totalRounds = askRounds()
	mode = askMode()

	iv = ''
	if(int(mode) > 1):
		iv = askIv()

	return {"name": name.upper(), "studentId": studentId, "totalRounds": totalRounds, "dob": dob, "mode": mode, "iv": iv, "originalName": originalName.upper()}

def getBinaryDataForInput(info):
  plainText = info['name'] + ' ' + info['studentId'] + '.'
  binary = getBinaryStringFor(plainText)
  return binary

def encryptWithSelectedMode(key, binary, totalRounds, mode, iv):
  	try:
		if(mode == 1):
			return encryptData(key, binary, totalRounds)
		elif(mode == 2):
			return encryptDataCbc(key, binary, totalRounds, iv)
		elif(mode == 3):
			return encryptDataOfb(key, binary, totalRounds, iv)
		elif(mode == 4):
			return encryptDataCtr(key, binary, totalRounds, iv)
		else:
			return {
				"des": encryptData(key, binary, totalRounds),
				"cbc": encryptDataCbc(key, binary, totalRounds, iv),
				"ofb": encryptDataOfb(key, binary, totalRounds, iv),
				"ctr": encryptDataCtr(key, binary, totalRounds, iv)
			}
	except Exception as e:
		print (e)
		return False

def encryptDataCbc(key, binary, totalRounds, iv):
  ivBinary = getBinaryStringFor(iv)
  binaryBlocks = generateTwelveBlockedData(binary)
  allBlockResult = ''
  
  for block in binaryBlocks:
		blockRes = generateDataForCbc(ivBinary, block, key, totalRounds)
		ivBinary = blockRes
		allBlockResult += blockRes
  return allBlockResult

def generateDataForCbc(ivBinary, binary, key, totalRounds):
	xorIvxPt = getBinaryForDigit(getXorValue(ivBinary, binary))
	xorIvxPt = prependZeroes(xorIvxPt, 12)
	blockCipherResult = encryptData(key, xorIvxPt, totalRounds)
	return blockCipherResult

def encryptDataOfb(key, binary, totalRounds, iv):
	ivBinary = getBinaryStringFor(iv)
	binaryBlocks = generateTwelveBlockedData(binary)
	allBlockResult = ''

	for block in binaryBlocks:
		blockRes = generateDataForOfb(ivBinary, block, key, totalRounds)
		ivBinary = blockRes['blockCipherResult']
		allBlockResult += blockRes['xorResult']
	return allBlockResult

def generateDataForOfb(ivBinary, binary, key, totalRounds):
	blockCipherResult = encryptData(key, ivBinary, totalRounds)
	xorBCrxPt = getBinaryForDigit(getXorValue(binary, blockCipherResult))
	xorBCrxPt = prependZeroes(xorBCrxPt, 12)
	return {"blockCipherResult": blockCipherResult, "xorResult": xorBCrxPt}

def encryptDataCtr(key, binary, totalRounds, iv):
	ivBinary = getBinaryStringFor(iv)
	binaryBlocks = generateTwelveBlockedData(binary)
	allBlockResult = ''

	for x in range(0, len(binaryBlocks)):
		counter = getBinaryForDigit(x)
		counter = prependZeroes(counter, 6)
		ctrInput = getBinaryForDigit(getXorValue(ivBinary, counter))
		blockRes = generateDataForCtr(ctrInput, binaryBlocks[x], key, totalRounds)
		allBlockResult += blockRes
	return allBlockResult

def generateDataForCtr(nonceCounter, binary, key, totalRounds):
	blockCipherResult = encryptData(key, nonceCounter, totalRounds)
	xorBCrxPt = getBinaryForDigit(getXorValue(binary, blockCipherResult))
	xorBCrxPt = prependZeroes(xorBCrxPt, 12)
	return xorBCrxPt

def encryptData(key, binary, totalRounds):
	binaryBlocks = generateTwelveBlockedData(binary)
	allBlockResult = ''
	
	for block in binaryBlocks:
		l0 = block[:6]
		r0 = block[6:]
		blockRes = generateDataForBlock(0, totalRounds, key, l0, r0)
		allBlockResult += blockRes
	return allBlockResult

def generateDataForBlock(currRound, totalRounds, key, left, right):
	edKey = getRoundKey(currRound, key)
	expRight = right[0:2] + right[3] + right[2] + right[3] + right[2] + right[4:]
	xorKeyxRight = getBinaryForDigit(getXorValue(edKey, expRight))
	xorKeyxRight = prependZeroes(xorKeyxRight, 8)
	nr = getS1ValueFor(xorKeyxRight[:4]) + getS2ValueFor(xorKeyxRight[4:])
	nextRight = getBinaryForDigit(getXorValue(left, nr))
	nextRight = prependZeroes(nextRight, 6)

	if(currRound < totalRounds-1):
		return generateDataForBlock(currRound+1, totalRounds, key, right, nextRight)
	elif(currRound == totalRounds-1):
		return nextRight + right
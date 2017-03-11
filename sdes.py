from helper import getInfo, getJulianDate, getNineBitKey, getBinaryDataForInput, encryptWithSelectedMode, printResult, askAction, getDecryptionInfo, decryptWithSelectedMode

print('============================== Simplified DES =============================================')

action = askAction()

if(action == 'E'):
	info = getInfo()
	julianDate = getJulianDate(info['dob'])
	key = getNineBitKey(julianDate)
	binary = getBinaryDataForInput(info)
	totalRounds = int(info['totalRounds'])
	result = encryptWithSelectedMode(key, binary, totalRounds, int(info['mode']), info['iv'])
	printResult(result, info)
elif(action == 'D'):
	decryptionInfo = getDecryptionInfo()
	print (decryptionInfo)
	dKey = getNineBitKey(getJulianDate(decryptionInfo['dob']))
	decryptedResult = decryptWithSelectedMode(dKey, decryptionInfo)
	print (decryptedResult)
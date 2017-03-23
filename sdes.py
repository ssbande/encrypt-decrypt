from helper import getInfo, getJulianDate, getNineBitKey, getBinaryDataForInput, encryptWithSelectedMode, printResult, askAction, getDecryptionInfo, decryptWithSelectedMode, printDecryptResult

print('============================== Simplified DES =============================================')

action = askAction()

if(action == 'E'):
	info = getInfo()
	julianDate = getJulianDate(info['dob'])
	key = getNineBitKey(julianDate)
	binary = getBinaryDataForInput(info)
	totalRounds = int(info['totalRounds'])
	result = encryptWithSelectedMode(key, binary, totalRounds, int(info['mode']), info['iv'])

	if(result == False):
		print("\nsome error occurred. check the input")
	else:
		printResult(result, info)
elif(action == 'D'):
	decryptionInfo = getDecryptionInfo()
	dKey = getNineBitKey(getJulianDate(decryptionInfo['dob']))
	decryptedResult = decryptWithSelectedMode(dKey, decryptionInfo)
	if(decryptedResult == False):
		print("\nsome error occurred. try again")
	else:
		printDecryptResult(decryptedResult, decryptionInfo)
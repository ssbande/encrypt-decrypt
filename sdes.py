from helper import getInfo, getJulianDate, getNineBitKey, getBinaryDataForInput, encryptWithSelectedMode, printResult, askAction, getDecryptionInfo, decryptWithSelectedMode, printDecryptResult, printEncryptDecryptResult, askEncryptedString

print('============================== DESPACITO =============================================')

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
elif(action == 'B'):
	info = getInfo()
	key = getNineBitKey(getJulianDate(info['dob']))
	binary = getBinaryDataForInput(info)
	totalRounds = int(info['totalRounds'])
	result = encryptWithSelectedMode(key, binary, totalRounds, int(info['mode']), info['iv'])
	decryptedResult = ''
	resultOk = True
	if(result == False):
		resultOk = False
	else:
		if(int(info['mode']) == 5):
			info['desEncData'] = result['des']
			info['cbcEncData'] = result['cbc']
			info['ofbEncData'] = result['ofb']
			info['ctrEncData'] = result['ctr']
		else:
			info['encData'] = result
		
		decryptResult = decryptWithSelectedMode(key, info)
		if(decryptResult == False):
			resultOk = False
		else:
			decryptedResult = decryptResult

	if(resultOk == False):
		print("\n Some error occurred in Encryption / Decryption")
	else:
		printEncryptDecryptResult(result, decryptedResult, info)

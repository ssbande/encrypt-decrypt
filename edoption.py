from helper import getJulianDate, getNineBitKey, printResult, askAction, printDecryptResult, printEncryptDecryptResult, askEncryptedString
from encryption import getInfo, getBinaryDataForInput, encryptWithSelectedMode
from decryption import getDecryptionInfo, decryptWithSelectedMode

print('============================== DESPACITO =============================================')

action = askAction()

if(action == 'E'):
	info = getInfo() 
	result = encryptWithSelectedMode(
    getNineBitKey(getJulianDate(info['dob'])), 
    getBinaryDataForInput(info), 
    int(info['totalRounds']), 
    int(info['mode']), 
    info['iv']
  )

	if(result == False):
		print("\nsome error occurred. check the input")
	else:
		printResult(result, info)
elif(action == 'D'):
	decryptionInfo = getDecryptionInfo()
	decryptedResult = decryptWithSelectedMode(
    getNineBitKey(getJulianDate(decryptionInfo['dob'])), 
    decryptionInfo
  )

	if(decryptedResult == False):
		print("\nsome error occurred. try again")
	else:
		printDecryptResult(decryptedResult, decryptionInfo)
elif(action == 'B'):
	info = getInfo()
	result = encryptWithSelectedMode(
    getNineBitKey(getJulianDate(info['dob'])), 
    getBinaryDataForInput(info), 
    int(info['totalRounds']), 
    int(info['mode']), 
    info['iv']
  )
  
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
		
		decryptResult = decryptWithSelectedMode(getNineBitKey(getJulianDate(info['dob'])), info)
		if(decryptResult == False):
			resultOk = False
		else:
			decryptedResult = decryptResult

	if(resultOk == False):
		print("\n Some error occurred in Encryption / Decryption")
	else:
		printEncryptDecryptResult(result, decryptedResult, info)

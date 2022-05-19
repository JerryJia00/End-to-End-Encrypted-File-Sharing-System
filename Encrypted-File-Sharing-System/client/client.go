package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username      string
	DataStoreKey  []byte
	HmacKey       []byte
	EncKey        []byte
	RSAPrivateKey userlib.PKEDecKey
	SignKey       userlib.DSSignKey

	own   map[string]userlib.UUID     // Both content of this and share should be decrypted by RSAPrivate Key
	share map[string]InvitationIDPair // UUID to the Pair{InvitationPtr, Sender's username}

	FileKeys map[string]FileKey // This is for user's own files

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

type FileKey struct {
	EncKey []byte

	// File MAC key
	HmacKey []byte
}

type File struct {
	// File Owner
	Owner string

	// File ID
	FileID userlib.UUID

	// Data
	Data []byte

	ChildrenList []string

	DirectChildren map[string]Invitation // Map recipientname to it's mailbox
}

type InvitationIDPair struct {
	InvitationPtr userlib.UUID

	SenderUsername string
}

type Invitation struct {
	MBEncKey []byte

	MBUUID userlib.UUID

	MBHmacKey []byte
}
type Mailbox struct {
	FileUUID userlib.UUID

	FileEncKey []byte

	FileHmacKey []byte
}

// NOTE: The following methods have toy (insecure!) implementations.
func GetUpdatedUser(userUUID userlib.UUID, EncKey []byte, HmacKey []byte) (userdataPtr *User, err error) {
	download_data, ok := userlib.DatastoreGet(userUUID)
	if !ok {
		return nil, errors.New("Fails to get the user, something went wrong")
	}
	var userdata User

	// Seperate the encrypted Data and Hmac tag
	EncyptLength := len(download_data) - userlib.HashSizeBytes
	EcryptedDataBytes := download_data[:EncyptLength]
	hmacTagDataBytes := download_data[EncyptLength:]
	newTag, err := userlib.HMACEval(HmacKey, EcryptedDataBytes)
	if err != nil {
		return nil, err
	}
	ok = userlib.HMACEqual(hmacTagDataBytes, newTag) // check if the two Hmac tags are equal
	if !ok {
		return nil, errors.New("The data loses Interity. Data loading fails")
	}

	// Decrypt and return the pointer
	DecryptedDataBytes := userlib.SymDec(EncKey, EcryptedDataBytes)
	err = json.Unmarshal(DecryptedDataBytes, &userdata)
	if err != nil {
		return
	}
	userdataPtr = &userdata
	return userdataPtr, nil
}
func InitUser(username string, password string) (userdataptr *User, err error) {
	if len(username) < 1 {
		return nil, errors.New("The username should not be empty")
	}

	var userdata User
	///Check whether these's repeated username
	_, ok := userlib.KeystoreGet(username)
	if ok {
		return nil, errors.New("The username already exists, please change to another one")
	}

	///Salt and RSA Key
	salt := string(userlib.Hash([]byte(username)))
	PKEEncKey, PKEDecKey, err := userlib.PKEKeyGen() // Public RSA, Private RSA, Error
	if err != nil {
		return nil, errors.New("Fail to PKEKeyGen().")
	}
	userlib.KeystoreSet(username, PKEEncKey) // Store the users' public key to keyStore API

	///Initialization
	userdata.Username = username
	// UUID since salt has username
	userdata.DataStoreKey = userlib.Argon2Key([]byte(password), []byte(salt), uint32(userlib.AESBlockSizeBytes))
	userdata.RSAPrivateKey = PKEDecKey

	// RSA Signature keys
	PrivateSignKey, PubVerifyKey, err := userlib.DSKeyGen()
	if err != nil {
		return nil, errors.New("Fail to DSKeyGen().")
	}
	userdata.SignKey = PrivateSignKey
	userlib.KeystoreSet(username+"DS", PubVerifyKey) // Store the users' public key to keyStore API

	// https://piazza.com/class/ky9e8cq86872u?cid=654_f10
	userdata.HmacKey = userlib.Argon2Key([]byte(password), []byte(salt), uint32(userlib.HashSizeBytes))[:16]
	//userdata.HmacKey = userlib.RandomBytes(userlib.HashSizeBytes)
	userdata.EncKey = userlib.Argon2Key([]byte(password), []byte(salt), uint32(userlib.AESBlockSizeBytes))

	userdata.share = make(map[string]InvitationIDPair)
	userdata.own = make(map[string]userlib.UUID)
	userdata.FileKeys = make(map[string]FileKey)

	/// To Data Store
	userBytes, err := json.Marshal(userdata)
	if err != nil {
		return nil, err
	}
	// CTR encrypt
	iv := userlib.RandomBytes(16)
	userBytesCRTencrypted := userlib.SymEnc(userdata.EncKey, []byte(iv), userBytes)
	// calculating the tag for Hmac
	HmacTag, err := userlib.HMACEval(userdata.HmacKey, userBytesCRTencrypted)
	if err != nil {
		return nil, err
	}
	userBytesCRTencryptedHmaced := append(userBytesCRTencrypted, HmacTag...)
	userUUID, err := uuid.FromBytes(userdata.DataStoreKey)
	if err != nil {
		return nil, err
	}
	// sned to the DS
	userlib.DatastoreSet(userUUID, userBytesCRTencryptedHmaced)

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	_, ok := userlib.KeystoreGet(username)
	if !ok {
		return nil, errors.New("The username doesn't exist, please create a new one")
	}

	// Get salt and the Key to the DS
	salt := userlib.Hash([]byte(username))
	DataStoreKey := userlib.Argon2Key([]byte(password), []byte(salt), uint32(userlib.AESBlockSizeBytes))

	// Get dataBytes
	userUUID, err := uuid.FromBytes(DataStoreKey)
	if err != nil {
		return nil, err
	}
	download_data, ok := userlib.DatastoreGet(userUUID)
	if !ok {
		return nil, errors.New("Fails to get the user, something went worng")
	}

	// Get original ENCKey and HmacKey
	HmacKey := userlib.Argon2Key([]byte(password), []byte(salt), uint32(userlib.HashSizeBytes))[:16]
	EncKey := userlib.Argon2Key([]byte(password), []byte(salt), uint32(userlib.AESBlockSizeBytes))

	// Seperate the encrypted Data and Hmac tag
	EncyptLength := len(download_data) - userlib.HashSizeBytes
	EcryptedDataBytes := download_data[:EncyptLength]
	hmacTagDataBytes := download_data[EncyptLength:]
	newTag, err := userlib.HMACEval(HmacKey, EcryptedDataBytes)
	if err != nil {
		return nil, err
	}
	ok = userlib.HMACEqual(hmacTagDataBytes, newTag) // check if the two Hmac tags are equal
	if !ok {
		return nil, errors.New("The data loses Interity. Data loading fails")
	}

	// Decrypt and return the pointer
	DecryptedDataBytes := userlib.SymDec(EncKey, EcryptedDataBytes)
	err = json.Unmarshal(DecryptedDataBytes, &userdata)
	if err != nil {
		return
	}
	userdataptr = &userdata
	return userdataptr, nil
}

func (userdata *User) EncryptFile(fileEncryptKey []byte, FileBytes []byte) (EncryptedFile []byte) {
	iv := userlib.RandomBytes(userlib.AESBlockSizeBytes)
	return userlib.SymEnc(fileEncryptKey, iv, FileBytes)

}

func (userdata *User) DecryptFile(fileUUID userlib.UUID, EncKey []byte, HmacKey []byte) (file File, err error) {
	/*
		userID, err := uuid.FromBytes(userdata.DataStoreKey)
		if err != nil {
			return err
		}
		userdata, err = GetUpdatedUser(userID, userdata.EncKey, userdata.HmacKey)
		if err != nil {
			return err
		}*/
	// Update user finished
	download_file, ok := userlib.DatastoreGet(fileUUID)
	if !ok {
		return file, errors.New("fail to find file")
	}

	EncyptLength := len(download_file) - userlib.HashSizeBytes
	if EncyptLength < 1 {
		return file, errors.New("Integrity loses 283")
	}
	FileBytes := download_file[:EncyptLength]
	hmacTagDataBytes := download_file[EncyptLength:]

	//userlib.DebugMsg("DecryptFile Enc and hmac", EncKey, HmacKey)
	newTag, err := userlib.HMACEval(HmacKey, FileBytes)
	if err != nil {
		return file, err
	}
	equal := userlib.HMACEqual(hmacTagDataBytes, newTag) // check if the two Hmac tags are equal
	if !equal {
		return file, errors.New("The File loses Interity. Data loading fails, line")
	}
	DecryptedFileBytes := userlib.SymDec(EncKey, FileBytes)
	var actual_file File
	json.Unmarshal(DecryptedFileBytes, &actual_file)
	return actual_file, nil
}

func (userdata *User) DecryptMB(fileUUID userlib.UUID, EncKey []byte, HmacKey []byte) (MB Mailbox, err error) {
	/*
		userID, err := uuid.FromBytes(userdata.DataStoreKey)
		if err != nil {
			return err
		}
		userdata, err = GetUpdatedUser(userID, userdata.EncKey, userdata.HmacKey)
		if err != nil {
			return err
		}*/
	// Update user finished
	download_file, ok := userlib.DatastoreGet(fileUUID)
	if !ok {
		return MB, errors.New("Cannot get the file")
	}

	EncyptLength := len(download_file) - userlib.HashSizeBytes

	FileBytes := download_file[:EncyptLength]
	hmacTagDataBytes := download_file[EncyptLength:]

	newTag, err := userlib.HMACEval(HmacKey, FileBytes)
	if err != nil {
		return MB, err
	}
	ok = userlib.HMACEqual(hmacTagDataBytes, newTag) // check if the two Hmac tags are equal
	if !ok {
		return MB, errors.New("The File loses Interity. Data loading fails, line")
	}

	DecryptedFileBytes := userlib.SymDec(EncKey, FileBytes)

	var actual_file Mailbox
	json.Unmarshal(DecryptedFileBytes, &actual_file)

	return actual_file, nil
}
func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	/*
		userID, err := uuid.FromBytes(userdata.DataStoreKey)
		if err != nil {
			return err
		}
		userdata, err = GetUpdatedUser(userID, userdata.EncKey, userdata.HmacKey)
		if err != nil {
			return err
		}*/
	// Update user finished
	// Check if the user has the same file locally
	if fileUUID, exist := userdata.own[filename]; exist {
		fileEncryptKey := userlib.RandomBytes(16)
		fileHmacKey := userlib.RandomBytes(16)

		// Restoring the previous file to get Children List and DirectChildren
		Old_fileEncryptKey := userdata.FileKeys[filename].EncKey
		Old_fileHmacKey := userdata.FileKeys[filename].HmacKey
		prev_file, err := userdata.DecryptFile(fileUUID, Old_fileEncryptKey, Old_fileHmacKey)
		if err != nil {
			return errors.New("System Crashes, StoreFile, line 266")
		}

		// Delete the original file so we can overwrite
		userlib.DatastoreDelete(fileUUID)

		file := File{userdata.Username, fileUUID, content, prev_file.ChildrenList, prev_file.DirectChildren}
		fileBytes, err := json.Marshal(file)
		if err != nil {
			return errors.New("System Crashes, StoreFile, line 266")
		}

		// Encrpt the new file
		EncryptedFile := userdata.EncryptFile(fileEncryptKey, fileBytes)
		HmacTag, err := userlib.HMACEval(fileHmacKey, EncryptedFile)
		if err != nil {
			return errors.New("System Crashes, StoreFile, line 271")
		}
		HmacEncryptedFile := append(EncryptedFile, HmacTag...)
		userlib.DatastoreSet(fileUUID, HmacEncryptedFile)

		// Add new filekey and filehmac to user and then re_encrypt user
		newFileKey := FileKey{fileEncryptKey, fileHmacKey}
		userdata.FileKeys[filename] = newFileKey
		userBytes, err := json.Marshal(userdata)
		if err != nil {
			return err
		}
		// CTR encrypt
		iv := userlib.RandomBytes(16)
		userBytesCRTencrypted := userlib.SymEnc(userdata.EncKey, []byte(iv), userBytes)

		// calculating the tag for Hmac
		userHmacTag, err := userlib.HMACEval(userdata.HmacKey, userBytesCRTencrypted)
		if err != nil {
			return err
		}
		userBytesCRTencryptedHmaced := append(userBytesCRTencrypted, userHmacTag...)
		userUUID, err := uuid.FromBytes(userdata.DataStoreKey)
		if err != nil {
			return err
		}
		// send to the DS
		userlib.DatastoreSet(userUUID, userBytesCRTencryptedHmaced)
		return nil

	} else if InvitationIDPair, exist := userdata.share[filename]; exist { // InvitationUUID
		invitationUUID := InvitationIDPair.InvitationPtr
		senderUsername := InvitationIDPair.SenderUsername
		invitationBytes, err := userdata.getInvitation(invitationUUID, senderUsername)
		if err != nil {
			return errors.New("System Crashes, StoreFile, line 405")
		}
		var invitation Invitation
		json.Unmarshal(invitationBytes, &invitation)
		// Get the Mailbox info
		MBUUID := invitation.MBUUID
		MBEncKey := invitation.MBEncKey
		MBHmacKey := invitation.MBHmacKey
		MB, err := userdata.DecryptMB(MBUUID, MBEncKey, MBHmacKey)
		if err != nil {
			return errors.New("System Crashes, StoreFile, line 414")
		}
		// Get the file info and file
		fileUUID := MB.FileUUID
		fileEncKey := MB.FileEncKey
		fileHmac := MBHmacKey
		file, err := userdata.DecryptFile(fileUUID, fileEncKey, fileHmac)
		if err != nil {
			return errors.New("System Crashes, StoreFile, line 421")
		}

		// change the file content
		file.Data = content // Overwrite here !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

		// *************************************Re-encrypt file*************************************
		fileBytes, err := json.Marshal(file)
		if err != nil {
			return errors.New("System Crashes, StoreFile, line 431")
		}
		// Encrpt the new file
		EncryptedFile := userdata.EncryptFile(fileEncKey, fileBytes)
		HmacTag, err := userlib.HMACEval(fileHmac, EncryptedFile)
		if err != nil {
			return errors.New("System Crashes, StoreFile, line 437")
		}
		HmacEncryptedFile := append(EncryptedFile, HmacTag...)
		userlib.DatastoreSet(fileUUID, HmacEncryptedFile)
		return nil
	} else {
		// The user does not have the file with the same name, so creat a new file and reencrypt the user
		fileUUID := uuid.New()
		//userlib.DebugMsg("Been in Store file, new file", fileUUID.String())
		fileEncryptKey := userlib.RandomBytes(16)
		fileHmacKey := userlib.RandomBytes(16)

		ChildList := make([]string, 0)
		DirectChild := make(map[string]Invitation)
		file := File{userdata.Username, fileUUID, content, ChildList, DirectChild}
		//userlib.DebugMsg("check map", len(DirectChild))
		fileBytes, err := json.Marshal(file)
		if err != nil {
			return errors.New("System Crashes, StoreFile, line 358")
		}
		// Encrpt the new file
		EncryptedFile := userdata.EncryptFile(fileEncryptKey, fileBytes)
		HmacTag, err := userlib.HMACEval(fileHmacKey, EncryptedFile)
		if err != nil {
			return errors.New("System Crashes, StoreFile, line 364")
		}
		HmacEncryptedFile := append(EncryptedFile, HmacTag...)
		userlib.DatastoreSet(fileUUID, HmacEncryptedFile)

		// Re_encrypt user

		// set new attribute to the user
		newFileKey := FileKey{fileEncryptKey, fileHmacKey}
		userdata.FileKeys[filename] = newFileKey
		userdata.own[filename] = fileUUID
		//userlib.DebugMsg("store file user EncKey", userdata.FileKeys[filename].EncKey, fileEncryptKey)
		//userlib.DebugMsg("store file user hmac", userdata.FileKeys[filename].HmacKey, fileHmacKey)
		// start enrypting
		userBytes, err := json.Marshal(userdata)
		if err != nil {
			return err
		}
		// CTR encrypt
		iv := userlib.RandomBytes(16)
		userBytesCRTencrypted := userlib.SymEnc(userdata.EncKey, []byte(iv), userBytes)

		// calculating the tag for Hmac
		userHmacTag, err := userlib.HMACEval(userdata.HmacKey, userBytesCRTencrypted)
		if err != nil {
			return err
		}
		userBytesCRTencryptedHmaced := append(userBytesCRTencrypted, userHmacTag...)
		userUUID, err := uuid.FromBytes(userdata.DataStoreKey)
		if err != nil {
			return err
		}
		// send to the DS
		userlib.DatastoreSet(userUUID, userBytesCRTencryptedHmaced)
		return nil
	}
	/*
		// Check if the user has the been shared with a file that has the same filename  // TODO This part should be deleted upon decision/////////////////////////////////////////////////////////////////////////////////
		if InvPtr, exist := userdata.share[filename]; exist {
			// The user has the filename shared with him/her
			// Rewrite the file
			EncryptedInvitation, ok := userlib.DatastoreGet(InvPtr)
			if !ok {
				return errors.New("System Crashes, StoreFile, line 278")
			}
			userlib.PKEDec(userdata.RSAPrivateKey, EncryptedInvitation)

		}

		storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
		if err != nil {
			return err
		}
		contentBytes, err := json.Marshal(content)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(storageKey, contentBytes)*/

}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	/*
		userID, err := uuid.FromBytes(userdata.DataStoreKey)
		if err != nil {
			return err
		}
		userdata, err = GetUpdatedUser(userID, userdata.EncKey, userdata.HmacKey)
		if err != nil {
			return err
		}*/
	// Update user finished

	if fileUUID, exist := userdata.own[filename]; exist {

		// Get the file
		fileEncryptKey := userdata.FileKeys[filename].EncKey
		fileHmacKey := userdata.FileKeys[filename].HmacKey
		file, err := userdata.DecryptFile(fileUUID, fileEncryptKey, fileHmacKey)
		//userlib.DebugMsg("file in append", file.Data)
		if err != nil {
			return errors.New("System Crashes, StoreFile, line 266")
		}

		// Append the content
		file.Data = append(file.Data, content...)
		// Re-encrypt the file could change to new key and hmac
		fileBytes, err := json.Marshal(file)
		/*
			var fileagain File
			json.Unmarshal(fileBytes, &fileagain)
			userlib.DebugMsg("file again", fileagain.Data, content)*/
		if err != nil {
			return errors.New("System Crashes, StoreFile, line 358")
		}
		EncryptedFile := userdata.EncryptFile(fileEncryptKey, fileBytes)
		HmacTag, err := userlib.HMACEval(fileHmacKey, EncryptedFile)
		if err != nil {
			return errors.New("System Crashes, StoreFile, line 364")
		}

		HmacEncryptedFile := append(EncryptedFile, HmacTag...)
		userlib.DatastoreDelete(fileUUID)
		userlib.DatastoreSet(fileUUID, HmacEncryptedFile)
		return nil
	} else if inviteIDPair, exist := userdata.share[filename]; exist {
		// Get the invitation
		invitePtr := inviteIDPair.InvitationPtr
		InviteBytes, err := userdata.getInvitation(invitePtr, inviteIDPair.SenderUsername)
		if err != nil {
			return errors.New("System Crashes, AppendToFile, line 472")
		}
		var actual_invitation Invitation
		json.Unmarshal(InviteBytes, &actual_invitation)

		// Get the information of Mailbox from the sender's invitation
		MBUUID := actual_invitation.MBUUID
		MBEncKey := actual_invitation.MBEncKey
		MBHmacKey := actual_invitation.MBHmacKey

		//Get the Mailbox
		MB, err := userdata.DecryptMB(MBUUID, MBEncKey, MBHmacKey)
		if err != nil {
			return errors.New("System Crashes, AppendToFile, line 485")
		}

		// Get the file
		file, err := userdata.DecryptFile(MB.FileUUID, MB.FileEncKey, MB.FileHmacKey)
		if err != nil {
			return errors.New("System Crashes, AppendToFile, line 485")
		}

		// Append the content
		file.Data = append(file.Data, content...)

		// Re-encrypt the file could change to new key and hmac
		fileBytes, err := json.Marshal(file)
		if err != nil {
			return errors.New("System Crashes, StoreFile, line 358")
		}
		EncryptedFile := userdata.EncryptFile(MB.FileEncKey, fileBytes)
		HmacTag, err := userlib.HMACEval(MB.FileHmacKey, EncryptedFile)
		if err != nil {
			return errors.New("System Crashes, StoreFile, line 364")
		}
		HmacEncryptedFile := append(EncryptedFile, HmacTag...)
		userlib.DatastoreSet(MB.FileUUID, HmacEncryptedFile)
		return nil
	}
	return errors.New("The filename does not exist")
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	/*
		userID, err := uuid.FromBytes(userdata.DataStoreKey)
		if err != nil {
			return err
		}
		userdata, err = GetUpdatedUser(userID, userdata.EncKey, userdata.HmacKey)
		if err != nil {
			return err
		}*/
	// Update user finished
	// check where's the file first
	if fileUUID, exist := userdata.own[filename]; exist {

		fileEncryptKey := userdata.FileKeys[filename].EncKey
		fileHmacKey := userdata.FileKeys[filename].HmacKey
		file, err := userdata.DecryptFile(fileUUID, fileEncryptKey, fileHmacKey)
		if err != nil {
			return nil, errors.New("System Crashes, StoreFile, line 266")
		}
		//userlib.DebugMsg("file content", file.Data)
		return file.Data, nil
	} else if InvitationIDPair, exist := userdata.share[filename]; exist {
		InvitationUUID := InvitationIDPair.InvitationPtr
		senderusername := InvitationIDPair.SenderUsername
		invitationBytes, err := userdata.getInvitation(InvitationUUID, senderusername)
		if err != nil {
			return nil, errors.New("System Crashes, LoadFile, line 620")
		}
		var invitation Invitation
		json.Unmarshal(invitationBytes, &invitation)
		//userlib.DebugMsg("What Bob get:", invitation.MBUUID, invitation.MBEncKey, invitation.MBHmacKey)
		MB, err := userdata.DecryptMB(invitation.MBUUID, invitation.MBEncKey, invitation.MBHmacKey)
		if err != nil {
			return nil, errors.New("System Crashes, LoadFile, line 626")
		}
		file, err := userdata.DecryptFile(MB.FileUUID, MB.FileEncKey, MB.FileHmacKey)
		if err != nil {
			return nil, errors.New("System Crashes, LoadFile, line 630")
		}
		return file.Data, nil

	}
	return nil, errors.New("The file does not exist")
}
func (userdata *User) getInvitation(invitePtr userlib.UUID, sender string) (invitationBytes []byte, err error) {
	/*
		userID, err := uuid.FromBytes(userdata.DataStoreKey)
		if err != nil {
			return err
		}
		userdata, err = GetUpdatedUser(userID, userdata.EncKey, userdata.HmacKey)
		if err != nil {
			return err
		}*/
	// Update user finished

	SignedEncryptedInvite, ok := userlib.DatastoreGet(invitePtr)
	if !ok {
		return nil, errors.New("The Invitation does not exist")
	}
	if len(SignedEncryptedInvite) < 256 {
		return nil, errors.New("The Invitation is tampered")
	}
	// Verify the signature by using the sender's public key
	SignedLength := len(SignedEncryptedInvite) - 256
	EcryptedInviteBytes := SignedEncryptedInvite[:SignedLength]
	signedInviteBytes := SignedEncryptedInvite[SignedLength:]
	senderPubVerifykey, ok := userlib.KeystoreGet(sender + "DS")
	if !ok {
		return nil, errors.New("The system crashes")
	}
	err = userlib.DSVerify(senderPubVerifykey, EcryptedInviteBytes, signedInviteBytes)
	if err != nil {
		return nil, errors.New("The message is not from the sender or it is tampered")
	}
	// Decrypt the Invitation using user(receiver)'s own RSA private key
	InviteBytes, err := userlib.PKEDec(userdata.RSAPrivateKey, EcryptedInviteBytes)
	if err != nil {
		return nil, errors.New("The system crashes")
	}

	return InviteBytes, nil
}
func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	/*
		userID, err := uuid.FromBytes(userdata.DataStoreKey)
		if err != nil {
			return err
		}
		userdata, err = GetUpdatedUser(userID, userdata.EncKey, userdata.HmacKey)
		if err != nil {
			return err
		}*/
	// Update user finished

	//check if the user is the owner of the file
	//userlib.DebugMsg("alice", userdata.Username, userdata.own[filename])
	if fileUUID, exist := userdata.own[filename]; exist {
		// Update ChildrenList and DirecChildren map and re-encrypt File
		//userlib.DebugMsg("Invitation stage EncKey and hmac", userdata.FileKeys[filename].EncKey, userdata.FileKeys[filename].HmacKey)
		file, err := userdata.DecryptFile(fileUUID, userdata.FileKeys[filename].EncKey, userdata.FileKeys[filename].HmacKey)

		if err != nil {
			return uuid.New(), err
		}
		file.ChildrenList = append(file.ChildrenList, recipientUsername)
		MBUUID := uuid.New()

		//********************* re-encrypt file ******************************

		// Create a mailbox
		MB := Mailbox{fileUUID, userdata.FileKeys[filename].EncKey, userdata.FileKeys[filename].HmacKey}
		MBEncryptKey := userlib.RandomBytes(16)
		MBHmacKey := userlib.RandomBytes(16)

		invitation := Invitation{MBEncryptKey, MBUUID, MBHmacKey}
		//userlib.DebugMsg("MB", MBUUID, MBEncryptKey, MBHmacKey)
		// Store it to the onwer's file so he/she can keep track of it
		file.DirectChildren[recipientUsername] = invitation
		// Encrpt the new file
		fileBytes, err := json.Marshal(file)
		if err != nil {
			return uuid.New(), errors.New("System Crashes, CreateInvitation, line 628")
		}

		EncryptedFile := userdata.EncryptFile(userdata.FileKeys[filename].EncKey, fileBytes)
		HmacTag, err := userlib.HMACEval(userdata.FileKeys[filename].HmacKey, EncryptedFile)
		if err != nil {
			return uuid.New(), errors.New("System Crashes, CreateInvitation, line 635")
		}
		HmacEncryptedFile := append(EncryptedFile, HmacTag...)
		userlib.DatastoreSet(fileUUID, HmacEncryptedFile)

		//**********************************Encrypt Mailbox ***********************************
		MBBytes, err := json.Marshal(MB)
		if err != nil {
			return uuid.New(), errors.New("System Crashes, CreateInvitation, line 646")
		}

		// Encrpt the new file
		EncryptedMB := userdata.EncryptFile(MBEncryptKey, MBBytes)
		MBHmacTag, err := userlib.HMACEval(MBHmacKey, EncryptedMB)
		if err != nil {
			return uuid.New(), errors.New("System Crashes, CreateInvitation, line 653")
		}
		HmacEncryptedMB := append(EncryptedMB, MBHmacTag...)
		userlib.DatastoreSet(MBUUID, HmacEncryptedMB) //  Send the MB to DataStore
		//********************************create Invitation******************************************

		InvitationByte, err := json.Marshal(invitation)
		if err != nil {
			return uuid.New(), errors.New("System Crashes, CreateInvitation, line 661")
		}
		RecipientPKEKey, ok := userlib.KeystoreGet(recipientUsername)
		if !ok {
			return uuid.New(), errors.New("The username does not exist")
		}
		EncryptedInvite, err := userlib.PKEEnc(RecipientPKEKey, InvitationByte) // PublicEnc using recipient's public rsa key
		if err != nil {
			return uuid.New(), errors.New("System Crashes, CreateInvitation, line 669")
		}
		//********************************* RSASign using sender's private RSA Key***********************
		Invite_sig, err := userlib.DSSign(userdata.SignKey, EncryptedInvite) // PkEEncKeygen() -> userdata.RSAPrivateKey, DSKeyGen()
		if err != nil {
			return uuid.New(), errors.New("System Crashes, CreateInvitation, line 674+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
		}
		SignedEncryptedInvite := append(EncryptedInvite, Invite_sig...)
		invitePtr := uuid.New()
		userlib.DatastoreSet(invitePtr, SignedEncryptedInvite)
		return invitePtr, err

	} else if inviteIDPair, exist := userdata.share[filename]; exist {

		// If the user itself is also being shared with this file, he/she should copy his/her invitation and create a new one based on his/her
		// Get the InvitePtr and the original sender from InvitePair -> get the actual Invitation
		invitePtr := inviteIDPair.InvitationPtr
		InviteBytes, err := userdata.getInvitation(invitePtr, inviteIDPair.SenderUsername)
		if err != nil {
			return uuid.New(), errors.New("System Crashes, CreateInvitation, line 550")
		}
		var actual_invitation Invitation
		json.Unmarshal(InviteBytes, &actual_invitation)

		// Copy the information from the sender's invitation
		MBUUID := actual_invitation.MBUUID
		MBEncKey := actual_invitation.MBEncKey
		MBHmacKey := actual_invitation.MBHmacKey

		// Create a new Invitation
		Invitation := Invitation{MBEncKey, MBUUID, MBHmacKey}
		InvitationByte, err := json.Marshal(Invitation)
		if err != nil {
			return uuid.New(), errors.New("System Crashes, CreateInvitation, line 266")
		}
		RecipientPKEKey, ok := userlib.KeystoreGet(recipientUsername)
		if !ok {
			return uuid.New(), errors.New("The recipient's username does not exist")
		}
		EncryptedInvite, err := userlib.PKEEnc(RecipientPKEKey, InvitationByte) // PublicEnc using recipient's public rsa key
		if err != nil {
			return uuid.New(), errors.New("System Crashes, CreateInvitation, line 266")
		}
		//********************************* RSASign using sender's private RSA Key***********************
		Invite_sig, err := userlib.DSSign(userdata.SignKey, EncryptedInvite)
		if err != nil {
			return uuid.New(), errors.New("System Crashes, CreateInvitation, line 266")
		}
		SignedEncryptedInvite := append(EncryptedInvite, Invite_sig...)

		// Getr another UUID for this copied Invitation
		invitePtr = uuid.New()
		userlib.DatastoreSet(invitePtr, SignedEncryptedInvite)
		return invitePtr, err

	}
	return uuid.New(), errors.New("The file does not exist, 723")
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	/*
		userID, err := uuid.FromBytes(userdata.DataStoreKey)
		if err != nil {
			return err
		}
		userdata, err = GetUpdatedUser(userID, userdata.EncKey, userdata.HmacKey)
		if err != nil {
			return err
		}*/
	// Update user finished
	// Check if the filename already exist locally
	if _, exist := userdata.own[filename]; exist {
		return errors.New("File already exist")
	}
	// TODO    Check same file and rename file, asked in piazza
	//
	//
	//
	//
	//
	// Get the actual Invitation and see if there's anything wrong about it
	invitePtr := invitationPtr
	invitationBytes, err := userdata.getInvitation(invitePtr, senderUsername)
	if err != nil {
		return errors.New("System Crashes, AcceptInvitation, line 597")
	}

	// create a new Invite Pair and map the filename to it
	newInviteIDPair := InvitationIDPair{invitationPtr, senderUsername}
	userdata.share[filename] = newInviteIDPair

	var actual_invitation Invitation
	json.Unmarshal(invitationBytes, &actual_invitation)
	MB, err := userdata.DecryptMB(actual_invitation.MBUUID, actual_invitation.MBEncKey, actual_invitation.MBHmacKey)
	if err != nil {
		return errors.New("System Crashes, LoadFile, line 626")
	}
	_, err = userdata.DecryptFile(MB.FileUUID, MB.FileEncKey, MB.FileHmacKey)
	if err != nil {
		return errors.New("System Crashes, LoadFile, line 630")
	}
	/*
		var actual_invitation Invitation
		json.Unmarshal(invitationBytes, &actual_invitation)



		// Anything else here?????????????????????????????????????????????????????????????????????????????????
		// add the receiver's name and info to the original file
		MB, err := userdata.DecryptMB(actual_invitation.MBUUID, actual_invitation.MBEncKey, actual_invitation.MBHmacKey)
		if err != nil {
			return errors.New("System Crashes, LoadFile, line 626")
		}
		file, err := userdata.DecryptFile(MB.FileUUID, MB.FileEncKey, MB.FileHmacKey)
		if err != nil {
			return errors.New("System Crashes, LoadFile, line 630")
		}*/

	// Re-encrypt userdata
	// Re_encrypt user
	// start enrypting
	userBytes, err := json.Marshal(userdata)
	if err != nil {
		return err
	}
	// CTR encrypt
	iv := userlib.RandomBytes(16)
	userBytesCRTencrypted := userlib.SymEnc(userdata.EncKey, []byte(iv), userBytes)

	// calculating the tag for Hmac
	userHmacTag, err := userlib.HMACEval(userdata.HmacKey, userBytesCRTencrypted)
	if err != nil {
		return err
	}
	userBytesCRTencryptedHmaced := append(userBytesCRTencrypted, userHmacTag...)
	userUUID, err := uuid.FromBytes(userdata.DataStoreKey)
	if err != nil {
		return err
	}
	// send to the DS
	userlib.DatastoreSet(userUUID, userBytesCRTencryptedHmaced)

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	/*
		userID, err := uuid.FromBytes(userdata.DataStoreKey)
		if err != nil {
			return err
		}
		userdata, err = GetUpdatedUser(userID, userdata.EncKey, userdata.HmacKey)
		if err != nil {
			return err
		}*/
	// Update user finished
	if fileUUID, exist := userdata.own[filename]; exist {
		file, err := userdata.DecryptFile(fileUUID, userdata.FileKeys[filename].EncKey, userdata.FileKeys[filename].HmacKey)
		if err != nil {
			return err
		}
		//userlib.DebugMsg("finding bob", file.DirectChildren, len(file.ChildrenList))
		if RecipInvitation, exist := file.DirectChildren[recipientUsername]; exist {
			//userlib.DebugMsg("Entered here")
			// Remove the recipient name from the master list of direct children of this file
			// Initializing new file key and hmac
			newfileEncryptKey := userlib.RandomBytes(16)
			newfileHmacKey := userlib.RandomBytes(16)
			for i, name := range file.ChildrenList {
				if name == recipientUsername {
					file.ChildrenList = append(file.ChildrenList[:i], file.ChildrenList[i+1:]...)
					delete(file.DirectChildren, recipientUsername)
				} else {
					invitation := file.DirectChildren[name]
					MB, err := userdata.DecryptMB(invitation.MBUUID, invitation.MBEncKey, invitation.MBHmacKey)
					if err != nil {
						return err
					}
					MB.FileEncKey = newfileEncryptKey
					MB.FileHmacKey = newfileHmacKey
					// Marshallizing
					MBBytes, err := json.Marshal(MB)
					if err != nil {
						return errors.New("System Crashes, CreateInvitation, line 646")
					}

					// Encrpt the new MB
					EncryptedMB := userdata.EncryptFile(invitation.MBEncKey, MBBytes)
					MBHmacTag, err := userlib.HMACEval(invitation.MBHmacKey, EncryptedMB)
					if err != nil {
						return errors.New("System Crashes, RevokeAccess, line 830")
					}
					HmacEncryptedMB := append(EncryptedMB, MBHmacTag...)
					userlib.DatastoreSet(invitation.MBUUID, HmacEncryptedMB) //  Send the MB to DataStore

				}
			}
			// After thee above for loop all the not revoked mailbox should store the new file info
			// Need to re-encrypt the file and user
			newFileKey := FileKey{newfileEncryptKey, newfileHmacKey}
			userdata.FileKeys[filename] = newFileKey
			//err = userdata.updateUser()
			if err != nil {
				return err
			}
			userlib.DatastoreDelete(RecipInvitation.MBUUID) // Remove this specific UUID
			// ***************************************re-encrypt the file***************************************
			fileBytes, err := json.Marshal(file)
			if err != nil {
				return err
			}
			EncryptedFile := userdata.EncryptFile(newfileEncryptKey, fileBytes)
			HmacTag, err := userlib.HMACEval(newfileHmacKey, EncryptedFile)
			if err != nil {
				return errors.New("System Crashes, revokeInvitation, line 635")
			}
			HmacEncryptedFile := append(EncryptedFile, HmacTag...)
			userlib.DatastoreSet(fileUUID, HmacEncryptedFile)

			//*********************************************re-encrypt the user***************************
			userBytes, err := json.Marshal(userdata)
			if err != nil {
				return err
			}
			// CTR encrypt
			iv := userlib.RandomBytes(16)
			userBytesCRTencrypted := userlib.SymEnc(userdata.EncKey, []byte(iv), userBytes)

			// calculating the tag for Hmac
			userHmacTag, err := userlib.HMACEval(userdata.HmacKey, userBytesCRTencrypted)
			if err != nil {
				return err
			}
			userBytesCRTencryptedHmaced := append(userBytesCRTencrypted, userHmacTag...)
			userUUID, err := uuid.FromBytes(userdata.DataStoreKey)
			if err != nil {
				return err
			}
			// send to the DS
			userlib.DatastoreSet(userUUID, userBytesCRTencryptedHmaced)
			return nil
		} else {
			return errors.New("Fail to revoke user because the recipient is not found")
		}

	}
	return errors.New("Fail to revoke user because the file does not exist")
}

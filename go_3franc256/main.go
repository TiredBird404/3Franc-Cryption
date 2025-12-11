package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

func main() {
	fmt.Println("3Franc Cryption ver.256bit-golang-terminal")
	var key []byte
	var menuContinue bool
	for {
		menuContinue = userMenu(&key)
		if !menuContinue {
			break
		}
	}
}

func userMenu(key *[]byte) bool {
	fmt.Println("\nPlease chose an option\n1. Set key\n2. Generate random key\n3. Encryption\n4. Decryption\n5. Quit")

	var userInput string
	fmt.Printf("Select: ")
	fmt.Scanln(&userInput)
	switch userInput {
	case "1":
		setKey(key)
	case "2":
		var err error = getRandomKey(key)
		if err != nil {
			fmt.Println("\nError:", err)
		}
	case "3":
		var err error = encryptionOption(*key)
		if err != nil {
			fmt.Println("\nError:", err)
		}
	case "4":
		var err error = decryptionOption(*key)
		if err != nil {
			fmt.Println("\nError:", err)
		}
	case "5":
		cleanKey(key)
		key = nil
		return false
	default:
		fmt.Println("\nError: no matching number was selected.")
	}
	return true
}

func setKey(key *[]byte) {
	fmt.Println("\nPlease enter your key.")
	fmt.Println("Notice: The key should not have any whitespace character.")
	var userInputKey string
	fmt.Printf("Key: ")
	fmt.Scanln(&userInputKey)
	fmt.Println("\nYour key:", userInputKey)
	*key = []byte(userInputKey)
}

func getRandomKey(key *[]byte) error {
	randomKey, err := GetRandomByte()
	if err != nil {
		return err
	}
	var hexKey string = hex.EncodeToString(randomKey)
	fmt.Println("\nYour key:", hexKey)
	*key = []byte(hexKey)
	return nil
}

func encryptionOption(key []byte) error {
	fileName, fileContent, err := getFileContent()
	if err != nil {
		return err
	}
	savePath, err := getFilePath()
	if err != nil {
		return err
	}
	fmt.Println("\nProcessing...")
	c := make(chan []byte)
	e := make(chan error)
	go getEncryptionResult(c, e)
	c <- fileContent
	c <- key
	err = <-e
	if err != nil {
		return err
	}
	var hexResult string = hex.EncodeToString(<-c)
	var resultContent string = insertNewlineEvery64Bytes(hexResult)
	err = saveFile(savePath, fileName, []byte(resultContent), "Encrypted")
	if err != nil {
		return err
	}
	return nil
}

func decryptionOption(key []byte) error {
	fileName, fileContent, err := getFileContent()
	if err != nil {
		return err
	}
	savePath, err := getFilePath()
	if err != nil {
		return err
	}
	fmt.Println("\nProcessing...")
	fileContent = removeWhitespaceCharacter(fileContent)
	contentToByte, err := hex.DecodeString(string(fileContent))
	if err != nil {
		return err
	}
	c := make(chan []byte)
	e := make(chan error)
	go getDecryptionResult(c, e)
	c <- contentToByte
	c <- key
	err = <-e
	if err != nil {
		return err
	}
	err = saveFile(savePath, fileName, <-c, "Decrypted")
	if err != nil {
		return err
	}
	return nil
}

func getEncryptionResult(c chan []byte, e chan error) {
	encryptionResult, err := Encryption(<-c, <-c)
	e <- err
	c <- encryptionResult
}

func getDecryptionResult(c chan []byte, e chan error) {
	decryptionResult, err := Decryption(<-c, <-c)
	e <- err
	c <- decryptionResult
}

func getFileContent() (string, []byte, error) {
	fmt.Println("\nPlease enter the file path containing your text to cryption.")
	var filePath string
	fmt.Printf("File: ")
	fmt.Scanln(&filePath)
	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		return "", nil, err
	}
	return getNameWithoutExt(filePath), fileContent, nil
}

func getFilePath() (string, error) {
	fmt.Println("\nPlease enter a path to save your cryption result.")
	var filePath string
	fmt.Printf("Path: ")
	fmt.Scanln(&filePath)
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return "", err
	} else if !fileInfo.IsDir() {
		return "", errors.New(filePath + "is a file")
	}
	return filePath, nil
}

func getNameWithoutExt(filePath string) string {
	fileName := filepath.Base(filePath)
	nameWithoutExt := strings.TrimSuffix(fileName, filepath.Ext(fileName))
	return nameWithoutExt
}

func saveFile(savePath string, fileName string, content []byte, resultType string) error {
	var newFilePath string = savePath + "/" + fileName + "_" + resultType
	newFile, err := os.Create(newFilePath)
	if err != nil {
		return err
	}
	defer newFile.Close()

	_, err = newFile.Write(content)
	if err != nil {
		return err
	}
	fmt.Println("\nThe cryption result is saved in", newFilePath)
	return nil
}

func insertNewlineEvery64Bytes(data string) string {
	var buffer bytes.Buffer
	var byteData []byte = []byte(data)
	chunkSize := 64

	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}

		buffer.Write(byteData[i:end])

		if end < len(data) {
			buffer.WriteByte('\n')
		}
	}

	return buffer.String()
}

func removeWhitespaceCharacter(content []byte) []byte {
	resultBytes := regexp.MustCompile(`\s+`).ReplaceAll(content, []byte(""))
	return resultBytes
}

func cleanKey(key *[]byte) {
	for i := range *key {
		(*key)[i] = 0
	}
}

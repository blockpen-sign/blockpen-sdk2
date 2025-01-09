export const CONTRACT_ABI = [
	{
		"anonymous": false,
		"inputs": [
			{
				"indexed": false,
				"internalType": "uint256",
				"name": "docID",
				"type": "uint256"
			}
		],
		"name": "DocumentLocked",
		"type": "event"
	},
	{
		"anonymous": false,
		"inputs": [
			{
				"indexed": false,
				"internalType": "uint256",
				"name": "docID",
				"type": "uint256"
			},
			{
				"indexed": false,
				"internalType": "uint256",
				"name": "size",
				"type": "uint256"
			},
			{
				"indexed": false,
				"internalType": "string",
				"name": "signedDigest",
				"type": "string"
			}
		],
		"name": "DocumentSigned",
		"type": "event"
	},
	{
		"inputs": [
			{
				"internalType": "string",
				"name": "initialDigest",
				"type": "string"
			},
			{
				"internalType": "uint256",
				"name": "docID",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "size",
				"type": "uint256"
			}
		],
		"name": "newDocument",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"anonymous": false,
		"inputs": [
			{
				"indexed": false,
				"internalType": "uint256",
				"name": "docID",
				"type": "uint256"
			},
			{
				"indexed": false,
				"internalType": "string",
				"name": "initialDigest",
				"type": "string"
			},
			{
				"indexed": false,
				"internalType": "uint256",
				"name": "size",
				"type": "uint256"
			}
		],
		"name": "NewDocument",
		"type": "event"
	},
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "docID",
				"type": "uint256"
			},
			{
				"internalType": "string",
				"name": "signedDigest",
				"type": "string"
			},
			{
				"internalType": "uint256",
				"name": "size",
				"type": "uint256"
			},
			{
				"internalType": "bool",
				"name": "lock",
				"type": "bool"
			}
		],
		"name": "signDocument",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"name": "documents",
		"outputs": [
			{
				"internalType": "string",
				"name": "initialDigest",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "finalHash",
				"type": "string"
			},
			{
				"internalType": "bool",
				"name": "isLocked",
				"type": "bool"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "string",
				"name": "docHash",
				"type": "string"
			}
		],
		"name": "getDocumentInfoByHash",
		"outputs": [
			{
				"internalType": "string",
				"name": "initialDigest",
				"type": "string"
			},
			{
				"internalType": "uint256[]",
				"name": "size",
				"type": "uint256[]"
			},
			{
				"internalType": "string[]",
				"name": "signedDigests",
				"type": "string[]"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "docID",
				"type": "uint256"
			}
		],
		"name": "getNumberOfSigners",
		"outputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "string",
				"name": "docHash",
				"type": "string"
			}
		],
		"name": "verifyDocument",
		"outputs": [
			{
				"internalType": "bool",
				"name": "",
				"type": "bool"
			}
		],
		"stateMutability": "view",
		"type": "function"
	}
]
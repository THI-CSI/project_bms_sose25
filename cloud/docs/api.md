# API Documentation

## Contents

- [API Documentation](#api-documentation)
  - [Contents](#contents)
  - [Battery Pass](#battery-pass)
    - [Request Body](#request-body)
    - [Path](#path)
    - [Response](#response)
    - [GET `/`](#get-)
      - [Description](#description)
    - [GET `/batterypass/`](#get-batterypass)
      - [Description](#description-1)
    - [PUT `/batterypass/{did}`](#put-batterypassdid)
      - [Description](#description-2)
      - [Body](#body)
      - [Example](#example)
    - [POST `/batterypass/{did}`](#post-batterypassdid)
      - [Description](#description-3)
      - [Body](#body-1)
      - [Example](#example-1)
    - [GET `/batterypass/{did}`](#get-batterypassdid)
      - [Description](#description-4)
      - [Query Parameters](#query-parameters)
      - [Example](#example-2)
    - [DELETE `/batterypass/{did}`](#delete-batterypassdid)
      - [Description](#description-5)
      - [Query Parameters](#query-parameters-1)
      - [Example](#example-3)

---

## Battery Pass

The API is available under <http://localhost:8000> by default.

For the following examples it is advised to export a sample `did` into your shell environment.
The keys that are registered inside [blockchain.test.json](../../blockchain/blockchain.test.json)
can be used to test the functionality of the API.
You can use `did:batterypass:bms.sn-544b51e7` as an example DID.

```shell
export EXAMPLE_DID="did:batterypass:bms.sn-544b51e7"
```

To generate the sample payloads, you can use:

```shell
python example/genpayloads.py did:batterypass:bms.sn-544b51e7 \
  did:batterypass:oem.sn-audi \
  example/testkeys/bms_decrypted_key.pem \
  example/testkeys/oem_decrypted_key.pem
```

This will create PUT, POST, GET and DELETE payloads 
signed and encrypted using `example/testkeys/bms_decrypted_key.pem`.
These payloads can be used to test the different endpoints.

---

### Request Body

All endpoints receive their body encrypted with the pre-discussed hybrid scheme.
The contents of the ciphertext payload differ from endpoint to endpoint, but the
overarching body is the same for all of them.

```jsonc
{
  "ciphertext": "...", // the encrypted contents of the actual body
  "aad": "...", // the nonce used for the encryption
  "salt": "...", // the salt used for the encryption
  "eph_pub": "...", // the ephemeral public key used for the ECDH key exchange
  "did": "...", // the DID of the sender, e.g., the OEM or the BMS itself
  "signature": "" // the signature over ciphertext + aad + salt + eph_pub + did
}
```

---

### Path

The path is the same for all endpoints excluding `/batterypass/` and `/`.
The `did` is the DID for the battery pass getting accessed.

---

### Response

The response can either be an acknowledgement that the operation has been
completed successfully:

```http
HTTP/1.1 200 OK

{ "ok": "..." }
```

or an error including the status code, specific error message and timestamp:

```http
HTTP/1.1 400 Bad Request

{
  "status": 400,
  "message": "Entry already exists.",
  "timestamp": "2025-05-27T10:30:00Z"
}
```

```http
HTTP/1.1 404 Not Found

{
  "status": 404,
  "message": "Entry doesn't exist.",
  "timestamp": "2025-05-27T10:30:00Z"
}
```

---

### GET `/`

#### Description

A health check to see if the API is up and running.

---

### GET `/batterypass/`

#### Description

Provides a list of DIDs for which a battery pass exists.

---

### PUT `/batterypass/{did}`

#### Description

The initial insertion needs to be sent to the battery pass endpoint with a PUT request.
It is either created by the OEM or the BMS itself.

#### Body

The body follows the [BatteryPassDataModel](https://github.com/batterypass/BatteryPassDataModel).
An example can be found in [example/batterypass.json](./example/batterypass.json). It needs to be
encapsulated inside the [request body](#request-body).

#### Example

```shell
curl -X PUT http://localhost:8000/batterypass/create/$EXAMPLE_DID \
  -H 'Content-Type: application/json' \
  --data @example/payloads/put_payload.json
```

---

### POST `/batterypass/{did}`

#### Description

To update one or more values within a battery pass for a specific `did`, you will need to provide a JSON list.
Each entry in this list should specify the path to the value you want to update and its new value:

```json
{ "path.to.value": "newValue" }
```

A proper example for such a list is as follows:

```json
[
  { "performance.batteryCondition.numberOfFullCycles": 6000 },
  { "performance.batteryCondition.remainingCapacity": 70 }
]
```

#### Body

The JSON list needs to be encrypted and encapsulated inside the [request body](#request-body).

#### Example

```shell
curl -X POST http://localhost:8000/batterypass/$EXAMPLE_DID \
  -H 'Content-Type: application/json' \
  --data @example/payloads/post_payload.json
```

---

### GET `/batterypass/{did}`

#### Description

Retrieving data can either be done with authentication (e.g., BMS / service access) or without it (public access).

#### Query Parameters

- public: set to `true` by default, needs to be set to `false` in order to access non-public data
- payload: A compact [request body](#request-body) serialized as a URL-safe JSON string

> [!NOTE]
> The encrypted ciphertext can either contain a **128-byte random number** (BMS access) or a Verifiable Presentation (e.g., service access).

#### Example

```shell
curl -X GET http://localhost:8000/batterypass/$EXAMPLE_DID?`cat example/payloads/get_payload.txt`
```

---

### DELETE `/batterypass/{did}`

#### Description

Deleting a battery pass can be achieved by sending a DELETE request to the battery pass endpoint.

> [!WARNING]
> The deletion is permanent and cannot be reverted

Since the request needs to be authenticated as having been sent by the BMS, a 128-byte random number
must be included so that the signature can be verified.

#### Query Parameters

- payload: A compact [request body](#request-body) serialized as a URL-safe JSON string

#### Example

```shell
curl -X DELETE http://localhost:8000/batterypass/$EXAMPLE_DID?`cat example/payloads/delete_payload.txt`
```

---

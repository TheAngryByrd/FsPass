namespace FsPass.Core

open System
open System.IO
open System.Threading
open System.Threading.Tasks
open Chessie.ErrorHandling
open Infrastructure
open PCLCrypto


module FsPassCore = 
    type FileSignature1 = 
        | FileSignature1 of uint32
    
    type FileSignature2 = 
        | FileSignature2 of uint32
    
    type FileVersion = 
        | FileVersion of uint32
    
    type VersionInfo = 
        { FileSignature1 : FileSignature1
          FileSignature2 : FileSignature2
          Version : FileVersion }
    
    let getFileVersionInfo (stream : Stream) = 
        async { 
            let! filesig1 = stream.AsyncRead(4) |> Async.map bytesTouint32
            let! fileSig2 = stream.AsyncRead(4) |> Async.map bytesTouint32
            let! version = stream.AsyncRead(4) |> Async.map bytesTouint32
            return { VersionInfo.FileSignature1 = FileSignature1 filesig1
                     FileSignature2 = FileSignature2 fileSig2
                     Version = FileVersion version }
        }
    
    module Kdb4Constants = 
        let FileSignature1 = FileSignature1 0x9AA2D903u
        let FileSignature2 = FileSignature2 0xB54BFB67u
    
    module Kdb1Constants = 
        let FileSignatureOld1 = FileSignature1 0x9AA2D903u
        let FileSignatureOld2 = FileSignature2 0xB54BFB65u
    
    type DatabaseFormat = 
        | Kdb of Stream
        | Kdbx of Stream
    
    let getDatabaseFormat stream (versionInfo : VersionInfo) = 
        if Kdb4Constants.FileSignature1 = versionInfo.FileSignature1 
           && Kdb4Constants.FileSignature2 = versionInfo.FileSignature2 then Kdbx stream |> Some
        elif Kdb1Constants.FileSignatureOld1 = versionInfo.FileSignature1 
             && Kdb1Constants.FileSignatureOld2 = versionInfo.FileSignature2 then Kdb stream |> Some
        else None
    
    module Decryption = 
        type Error = 
            | FileSignaturesDoNotMatch
            | KdbNotSupported
            | InvalidHeaders
        
        type Headers = 
            | EndOfHeader = 0
            | Comment = 1
            | CipherID = 2
            | CompressionFlags = 3
            | MasterSeed = 4
            | TransformSeed = 5
            | TransformRounds = 6
            | EncryptionIV = 7
            | ProtectedStreamKey = 8
            | StreamStartBytes = 9
            | InnerRandomStreamID = 10
        
        type PwCompressionAlgorithm = 
            | None = 0
            | Gzip = 1
            | Count = 2
        
        type CrsAlgorithm = 
            | Null = 0
            | ArcFourVariant = 1
            | Salsa20 = 2
            | Count = 3
        
        type HeadersWithValueOption = 
            { Comment : string option
              CipherID : byte array option
              CompressionFlags : PwCompressionAlgorithm option
              MasterSeed : byte array option
              TransformSeed : byte array option
              TransformRound : uint64 option
              EncryptionIV : byte array option
              ProtectedStreamKey : byte array option
              StreamStartBytes : byte array option
              InnerRandomStreamID : CrsAlgorithm option }
        
        let emptyHeadersWithValueOption = 
            { Comment = None
              CipherID = None
              CompressionFlags = None
              MasterSeed = None
              TransformSeed = None
              TransformRound = None
              EncryptionIV = None
              ProtectedStreamKey = None
              StreamStartBytes = None
              InnerRandomStreamID = None }
        
        type HeadersWithValue = 
            { Comment : string option
              CipherID : byte array
              CompressionFlags : PwCompressionAlgorithm
              MasterSeed : byte array
              TransformSeed : byte array
              TransformRound : uint64
              EncryptionIV : byte array
              ProtectedStreamKey : byte array
              StreamStartBytes : byte array
              InnerRandomStreamID : CrsAlgorithm }
        type PasswordHash = PasswordHash of byte array 
        type KeyFileHash = KeyFileHash of byte array
        type CompositeKey = CompositeKey of byte array
        
        let headersWithValueFromOption (h : HeadersWithValueOption) = 
            match h with
            | _ when h.CipherID.IsNone || h.CompressionFlags.IsNone || h.MasterSeed.IsNone || h.TransformSeed.IsNone 
                     || h.TransformRound.IsNone || h.EncryptionIV.IsNone || h.ProtectedStreamKey.IsNone 
                     || h.StreamStartBytes.IsNone || h.InnerRandomStreamID.IsNone -> InvalidHeaders |> fail
            | _ -> 
                { HeadersWithValue.Comment = h.Comment
                  CipherID = h.CipherID.Value
                  CompressionFlags = h.CompressionFlags.Value
                  MasterSeed = h.MasterSeed.Value
                  TransformSeed = h.TransformSeed.Value
                  TransformRound = h.TransformRound.Value
                  EncryptionIV = h.EncryptionIV.Value
                  ProtectedStreamKey = h.ProtectedStreamKey.Value
                  StreamStartBytes = h.StreamStartBytes.Value
                  InnerRandomStreamID = h.InnerRandomStreamID.Value }
                |> ok
        
        let FromHeaderValue (header, value) (headersWithValueOption : HeadersWithValueOption) = 
            match header with
            | Headers.EndOfHeader -> headersWithValueOption
            | Headers.Comment -> 
                { headersWithValueOption with Comment = 
                                                  value
                                                  |> bytesToString
                                                  |> Some }
            | Headers.CipherID -> { headersWithValueOption with CipherID = Some value }
            | Headers.CompressionFlags -> 
                { headersWithValueOption with CompressionFlags = 
                                                  value
                                                  |> bytesTouint32
                                                  |> int
                                                  |> enum<PwCompressionAlgorithm>
                                                  |> Some }
            | Headers.MasterSeed -> { headersWithValueOption with MasterSeed = Some value }
            | Headers.TransformSeed -> { headersWithValueOption with TransformSeed = Some value }
            | Headers.TransformRounds -> 
                { headersWithValueOption with TransformRound = 
                                                  value
                                                  |> bytesTouint64
                                                  |> Some }
            | Headers.EncryptionIV -> { headersWithValueOption with EncryptionIV = Some value }
            | Headers.ProtectedStreamKey -> { headersWithValueOption with ProtectedStreamKey = Some value }
            | Headers.StreamStartBytes -> { headersWithValueOption with StreamStartBytes = Some value }
            | Headers.InnerRandomStreamID -> 
                { headersWithValueOption with InnerRandomStreamID = 
                                                  value
                                                  |> bytesTouint32
                                                  |> int
                                                  |> enum<CrsAlgorithm>
                                                  |> Some }
            | _ -> headersWithValueOption
        
        let rec getHeaders fromHeaderValue state (stream : Stream) = 
            async { 
                let header = stream.ReadByte() |> enum<Headers>
                let! valueSize = stream.AsyncRead 2
                                 |> Async.map bytesTouint16
                                 |> Async.map int
                let! valueBytes = stream.AsyncRead valueSize
                let headerValue = fromHeaderValue (header, valueBytes) state
                match header with
                | Headers.EndOfHeader -> return headerValue
                | _ -> return! getHeaders fromHeaderValue headerValue stream
            }
        
        let getHeaders' state stream = (getHeaders FromHeaderValue state stream) |> Async.map headersWithValueFromOption


        let rec transFormTimes transformForKey transformSeed rawCompositeKey (rounds : uint64) = 
            match rounds with
            | 0UL -> rawCompositeKey
            | _ ->
                let result = transformForKey transformSeed rawCompositeKey
                transFormTimes transformForKey transformSeed result (rounds - 1UL) 

        let transformKey transformForKey (CompositeKey rawCompositeKey) transformSeed rounds = async {
            

            let t1 = 
                async { 
                    return transFormTimes transformForKey transformSeed (rawCompositeKey
                                               |> Seq.take (16)
                                               |> Seq.toArray) rounds
                }
            
            let t2 = 
                async { 
                    return transFormTimes transformForKey transformSeed (rawCompositeKey
                                               |> Seq.skip (16)
                                               |> Seq.take (16)
                                               |> Seq.toArray) rounds
                }
            let! results = [ t1; t2 ] |> Async.Parallel
            return Array.concat results
           }




        let generateAesKey hasher transformer (compositeKey : CompositeKey) masterSeed transformSeed transformRounds = 
            async { 
                let! transformedKey = transformer compositeKey transformSeed transformRounds |> Async.map hasher
                let hashedTransformedKey = Array.append masterSeed transformedKey |> hasher
                return hashedTransformedKey
            }


        let createCompositeKey hasher (password : PasswordHash option) (keyFile : KeyFileHash option) : CompositeKey = 
            match password, keyFile with
            | Some (PasswordHash p), Some (KeyFileHash k) -> Array.append p k |> hasher
            | Some (PasswordHash p), None -> p |> hasher
            | None, Some (KeyFileHash k) -> k |> hasher
            | _, _ -> [||]
            |> CompositeKey

        let decryptDatabase decryptKdbxDatabase (database : DatabaseFormat option) (versionInfo : VersionInfo) = 
            match database with
            | None -> FileSignaturesDoNotMatch |> fail
            | Some d -> 
                match d with
                | Kdb _ -> KdbNotSupported |> fail
                | Kdbx s -> decryptKdbxDatabase s versionInfo

module PclCrypto =
    let hasher256 (bytes : byte array) : byte array =
        let sha256 =  WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(PCLCrypto.HashAlgorithm.Sha256)
        sha256.HashData(bytes)
       
    let transformForKey' key data =
            let aesProvider = WinRTCrypto.SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithm.AesEcb)
            let transformKey = aesProvider.CreateSymmetricKey key
            let result = WinRTCrypto.CryptographicEngine.Encrypt(transformKey, data, null)
            result

module AppliedPCL =
   let transformKeyPcl = FsPassCore.Decryption.transformKey PclCrypto.transformForKey'
   let generateAesKeyPcl =  FsPassCore.Decryption.generateAesKey PclCrypto.hasher256 transformKeyPcl
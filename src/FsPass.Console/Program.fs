// Learn more about F# at http://fsharp.org
// See the 'F# Tutorial' project for more help.
open System
open System.IO
open FsPass.Core
open Infrastructure
let getFileAsInMemoryStream path = new MemoryStream(File.ReadAllBytes(path))

let bench name f x = async {
    let sw = System.Diagnostics.Stopwatch.StartNew()
    let! result = f x
    sw.Stop(); printfn "%s took %d ms" name sw.ElapsedMilliseconds
    return result
}
open System.Security.Cryptography

let TransformManageed key data =
    let aes = new AesManaged(KeySize = 256, IV = Array.zeroCreate (16), Key = key)
    let outBytes = Array.zeroCreate 16
    aes.CreateEncryptor().TransformBlock(data, 0, 16, outBytes, 0) |> ignore
    outBytes

[<EntryPoint>]
let main argv =
    let keePassPath = argv.[0] |> string
    if System.isMono then printfn "mono"
    else printfn ".net"

    use stream = getFileAsInMemoryStream keePassPath
    let versionInfo = FsPassCore.getFileVersionInfo stream |> Async.RunSynchronously
    printfn "%A" versionInfo
    let databaseFormat = FsPassCore.getDatabaseFormat stream versionInfo
    printfn "%A" databaseFormat
    let headers = FsPassCore.Decryption.getHeaders' FsPassCore.Decryption.emptyHeadersWithValueOption stream |> Async.RunSynchronously |> Chessie.ErrorHandling.Trial.returnOrFail

    printfn "%A" headers

    let passwordInByts = System.Text.UTF8Encoding.UTF8.GetBytes("password") |> PclCrypto.hasher256 |> FsPassCore.Decryption.PasswordHash
    let compositeKey = FsPassCore.Decryption.createCompositeKey PclCrypto.hasher256 (Some passwordInByts) None
    let (FsPassCore.Decryption.CompositeKey compiteKey') = compositeKey
    printfn "%s" (Convert.ToBase64String compiteKey')
    printfn "%s" "c2Qcmfdxn1fY9L6xGjA6/NGQJDpRzth4LKbT2+AU0UY="

    [1..3]
    |> Seq.iter(fun _ ->
            bench "generateAesKeyPcl" ( AppliedPCL.generateAesKeyPcl compositeKey headers.MasterSeed headers.TransformSeed ) (headers.TransformRound * 20UL)
            |> Async.Ignore
            |> Async.RunSynchronously
    )
    let managedTransformer = FsPassCore.Decryption.generateAesKey PclCrypto.hasher256 (FsPassCore.Decryption.transformKey TransformManageed)
    [1..3]
    |> Seq.iter(fun _ ->
            bench "generateAesKeyManaged" ( managedTransformer compositeKey headers.MasterSeed headers.TransformSeed ) (headers.TransformRound * 200UL)
            |> Async.Ignore
            |> Async.RunSynchronously
    )
    let hashedTransformedKey = AppliedPCL.generateAesKeyPcl compositeKey headers.MasterSeed headers.TransformSeed  headers.TransformRound |> Async.RunSynchronously


    hashedTransformedKey
    |> Convert.ToBase64String
    |> printfn "%s"
    printfn "%s" "919V0/MeMJ8JCjxeYxT3IvsWX2crmcET8Cz/rCh7zcA="
    Console.ReadLine() |> ignore
    0 // return an integer exit code

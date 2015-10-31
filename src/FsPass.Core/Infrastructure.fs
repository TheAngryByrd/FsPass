module Infrastructure
open System
[<AutoOpen>]
module Async =
    open System.Threading.Tasks

    let inline awaitPlainTask (task : Task) =
        // rethrow exception from preceding task if it fauled
        let continuation (t : Task) : unit =
            match t.IsFaulted with
            | true -> raise t.Exception
            | arg -> ()
        task.ContinueWith continuation |> Async.AwaitTask

    let inline startAsPlainTask (work : Async<unit>) = Task.Factory.StartNew(fun () -> work |> Async.RunSynchronously)
    let inline ofValue x = async { return x }

[<AutoOpen>]
module Bytes =

    let bytesTouint64 bytes = BitConverter.ToUInt64(bytes, 0)
    let bytesTouint32 bytes = BitConverter.ToUInt32(bytes, 0)
    let bytesTouint16 bytes = BitConverter.ToUInt16(bytes, 0)
    let bytesToString bytes = BitConverter.ToString bytes
[<AutoOpen>]
module System =
    let isMono = Type.GetType("Mono.Runtime") |> isNull

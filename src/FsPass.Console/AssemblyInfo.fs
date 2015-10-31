namespace System
open System.Reflection

[<assembly: AssemblyTitleAttribute("FsPass.Console")>]
[<assembly: AssemblyProductAttribute("FsPass")>]
[<assembly: AssemblyDescriptionAttribute("FsPass")>]
[<assembly: AssemblyVersionAttribute("1.0")>]
[<assembly: AssemblyFileVersionAttribute("1.0")>]
do ()

module internal AssemblyVersionInformation =
    let [<Literal>] Version = "1.0"

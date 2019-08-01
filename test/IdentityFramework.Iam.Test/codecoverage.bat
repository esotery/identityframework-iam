cd IdentityFramework.Iam.Test
dotnet test /p:CollectCoverage=true /p:CoverletOutput="test" /p:Exclude=\"[IdentityFramework.Iam.Ef]*,[IdentityFramework.Iam.TestServer]*\"

cd ..\IdentityFramework.Iam.Ef.Test
dotnet test /p:CollectCoverage=true /p:CoverletOutputFormat="opencover" /p:CoverletOutput="test" /p:Exclude=\"[IdentityFramework.Iam.Core]*,[IdentityFramework.Iam.TestServer]*\" /p:MergeWith="..\IdentityFramework.Iam.Test\test.json"

dotnet reportgenerator "-reports:test.opencover.xml" "-targetdir:reports"

cd ..
/** Deliberate source-policy rejection; no token, network or raw error output. */
import { resolve, join } from 'node:path';
import { pathToFileURL } from 'node:url';
const {admitPublicationPolicy}=await import(pathToFileURL(join(resolve(process.env.FIXTURE_SOURCE_DIRECTORY),'scripts/publication-authority.mjs')));
let code='UNEXPECTED_ACCEPTANCE';
try{admitPublicationPolicy(Buffer.from(process.env.TABGRAD_RELEASE_POLICY_JSON),'0'.repeat(64));}
catch(error){code=/^[A-Z][A-Z0-9_]*$/.test(error.code??'')?error.code:'UNEXPECTED_ERROR';}
process.stdout.write(JSON.stringify({fixture:true,code,githubCredential:Boolean(process.env.GH_TOKEN||process.env.GITHUB_TOKEN)})+'\n');
if(code!=='PUBLICATION_POLICY_IDENTITY')process.exitCode=1;

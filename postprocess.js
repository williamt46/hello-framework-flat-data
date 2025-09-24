// The Flat Data postprocessing libraries can be found at https://deno.land/x/flat/mod.ts
// Replace 'x' with latest library version
import { readJSON, writeJSON } from 'https://deno.land/x/flat@0.0.x/mod.ts'

const filename = Deno.args[0] // equivalent to writing `const filename = 'btc-price.json'`
const data = await readJSON(filename)
console.log(data)   

//filter for specific data


// pluck a specific key off and write it out to a new file
const newfileName = `postprocessed_${filename}`
await writeJSON(newfile, data.path.to.something)
console.log(`wrote a post process file ${newfileName}`)
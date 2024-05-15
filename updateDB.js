const axios = require('axios');
const mongoose = require('mongoose');

const uri = "mongodb://localhost:27017/Securin";
mongoose.connect(uri, { useNewUrlParser: true, useUnifiedTopology: true });
let myColl;
mongoose.connection.on('connected', () => {
    console.log('Connected to MongoDB');
    myColl = mongoose.connection.db.collection('cves');
});

async function updateDB(offset){
 const apiUrl = 'https://services.nvd.nist.gov/rest/json/cvehistory/2.0';
 let off = offset;
  try {while (true) {
            const response = await axios.get(apiUrl, { params: {startIndex: off,resultsPerPage:1}});
            const historyPageData = response.data;
            const histLen = historyPageData.totalResults;
            if(histLen!==localLen){
                const newcount = histLen - localLen;
                const newResponse = await axios.get(apiUrl, { params: {startIndex: newcount,resultsPerPage:localLen}});
                const newhistoryres = newResponse.data;
                for(let j=0;j<newcount;j++){
                    const change = newhistoryres.cveChanges[j].change;
                    if (newhistoryres.cveChanges[j].eventName === "CVE Rejected") {
                        await myColl.findOneAndDelete({ id: change.cveId }) }
                    else{ 
const cveDetailsResponse = await axios.get(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${change.cveId}`);
                        const cveDetailsResult = await cveDetailsResponse.json();
                        console.log(cveDetailsResult.vulnerabilities[0]);
                        const item = cveDetailsResult.vulnerabilities[0].cve;
                        item._id = cveDetailsResult.vulnerabilities[0].id;
                        await myColl.updateOne({ _id: cveData.id }, { $set: cveData }, { upsert: true });
                        await new Promise(resolve => setTimeout(resolve, 100000));}}
               localLen+=newcount;
                console.log(`Updated DB with ${newcount} records`);} 
        else{console.log("DB is in sync");}}}
catch (error) {console.error("An error occurred:", error);}}

setInterval(()=>{
    updateDB(0),30*60*1000
})    

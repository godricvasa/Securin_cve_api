const axios = require('axios');
const mongoose = require('mongoose');

const uri = "mongodb://localhost:27017/Securin";
mongoose.connect(uri, { useNewUrlParser: true, useUnifiedTopology: true });

async function getAllData() {
    const apiUrl = 'https://services.nvd.nist.gov/rest/json/cvehistory/2.0';
    const resultsPerPage = 2000;
    let offset = 0;

    try {
        while (true) {
            const response = await axios.get(apiUrl, {
                params: {
                    startIndex: offset,
                    resultsPerPage
                }
            });
            console.log('yo');
            const currentPageData = response.data;
            const changes = currentPageData.cveChanges || [];

            // Insert each CVE object directly into MongoDB
            for (const { cve } of changes) {
                // Specify cveId as the _id field to prevent duplicates
                const cveId = cve.cveId;
                
                if(cve.eventName==="CVE Rejected"){
                    await mongoose.connection.db.collection('cve').deleteOne({_id:cveId});
                }
                else{
                    await mongoose.connection.db.collection('cve').updateOne({ _id: cveId }, { $set: cve }, { upsert: true });

                }
            }
            

            offset += resultsPerPage;

            await new Promise(resolve => setTimeout(resolve, 10000)); // Adjust the delay time as needed
        }
    } catch (error) {
        console.error('Error fetching data:', error.message);
    }
}

getAllData();
//data cleansing remove all the rejected cves;
async function cleansing(){
    await mongoose.connection.db.collection('Secure').deleteMany({ vulnstatus: "Rejected" });
}
cleansing();

console.log('DB is done');

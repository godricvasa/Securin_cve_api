const axios = require('axios');
const mongoose = require('mongoose');

const uri = "mongodb://localhost:27017/Securin";
mongoose.connect(uri, { useNewUrlParser: true, useUnifiedTopology: true });

async function populate(offset) {
    const apiUrl = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
    const resultsPerPage = 2000;
   let offset = offset;

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
            const vulnerabilities = currentPageData.vulnerabilities || [];

            for (const { cve } of vulnerabilities) {
               
                const cveId = cve.id;
                await mongoose.connection.db.collection('Secure').updateOne({ _id: cveId }, { $set: cve }, { upsert: true });
            }

            offset += resultsPerPage;

            await new Promise(resolve => setTimeout(resolve, 10000)); 
        }
    } catch (error) {
        console.error('Error fetching data:', error.message);
    }
}

populate(0);
//data cleansing remove all the rejected cves;
async function cleansing(){
    await mongoose.connection.db.collection('Secure').deleteMany({ vulnstatus: "Rejected" });
}
cleansing();

console.log('DB is done');
export default getAllData;
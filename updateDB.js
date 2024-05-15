const axios = require('axios');
const mongoose = require('mongoose');

const uri = "mongodb://localhost:27017/Securin";
mongoose.connect(uri, { useNewUrlParser: true, useUnifiedTopology: true });

async function fetchUpdate (start_index=0, per_page=2000) {
    const apiurl = "https://services.nvd.nist.gov/rest/json/cvehistory/2.0";
    const last_date = "1999";
    const offset = {
        "startIndex": start_index,
        "resultsPerPage": per_page,
        "start date": last_date
    };
    try {
        const req = await axios.get(apiurl, { params: offset });
        // get status code 
        const status = req.status;
        if(status === 200) {
            const data = req.data;
            return {data, status};
        } else {
            console.log('No result');
            return {data: {}, status};
        }
    } catch (error) {
        console.error(`Error: ${error}`);
        return {data: {}, status: error.response ? error.response.status : 'Unknown error'};
    }
}

async function handleUpdate() {
    let start_index = 0;
    const per_page = 2000;
    while (true) {
        const { status, data } = await fetchUpdate(start_index, per_page);
        if (status === 200) start_index += per_page;
        else {
            await new Promise(resolve => setTimeout(resolve, 5000));
            continue;
        }
        if (data.resultsPerPage === 0) break;
        for (const { change } of data.cveChanges) {
            const cveId = change.cveId;
            if (change.eventName === "CVE Rejected") {
                await mongoose.connection.db.collection('Secure').deleteOne({ _id: cveId });
            } else {
                const cveResponse = await axios.get('https://services.nvd.nist.gov/rest/json/cves/2.0', {
                    params: {
                        cveId,
                        startIndex: start_index,
                        resultsPerPage: per_page
                    }
                });
                if(cveResponse.data.vulnerabilities && cveResponse.data.vulnerabilities[0]) {
                    const cveData = cveResponse.data.vulnerabilities[0].cve;
                    await mongoose.connection.db.collection('Secure').updateOne({ _id: cveData.id }, { $set: cveData }, { upsert: true });
                }
            }      
         }
        }
    }
 setInterval(handleUpdate,30*60*1000);








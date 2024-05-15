const express = require('express');
const mongoose = require('mongoose');
const app = express();
const ejs = require('ejs');
const bodyParser = require('body-parser');

app.use(express.static('public'));
app.set('view engine', 'ejs');

const uri = "mongodb://localhost:27017/Securin";
mongoose.connect(uri, { useNewUrlParser: true, useUnifiedTopology: true });
let myColl;

mongoose.connection.on('connected', async() => {
    console.log('Connected to MongoDB');
    myColl = mongoose.connection.db.collection('Secure');
});


app.use(bodyParser.urlencoded({ extended: true }));
   // Format date on frontend
   function formatDate(dateString) {
    const date = new Date(dateString);
    const options = { day: '2-digit', month: 'long', year: 'numeric' };
    const formattedDate = date.toLocaleDateString('en-GB', options);
    return formattedDate;
}

const perPage = 20; 
//Main page route for viewing all the cve data

app.get('/cves/list', async (req, res) => {
    const page = req.query.page;
    const perPage = parseInt(req.query.perPage) || 10;
    const year = req.query.year || "";
    const lastmodified = parseInt(req.query.lastModified) || -1;
    const lt = parseFloat(req.query.lt) || 10.0;
    const gt = parseFloat(req.query.gt) || 0.0;
    const id = req.query.SearchId || "";
    try {
        const totalCount = await myColl.countDocuments();
        
        const offset = (page - 1) * perPage; 
    const query = {
          "_id":{$regex:id},
          "published": {"$regex": year},
          "$or": [
            { "metrics.cvssMetricV2.cvssData.baseScore": { "$gte": gt, "$lte": lt } },
            { "metrics.cvssMetricV3.cvssData.baseScore": { "$gte": gt, "$lte": lt } }
        ]   
       };
       let cve;
       if(lastmodified==-1){ cve = await myColl.find(query).sort({published:1}).skip(offset).limit(perPage).toArray();
       }
       else{
         cve = await myColl.find(query).sort({lastModified:-1}).skip(offset).limit(lastmodified).toArray();
       }
      let tot = await myColl.countDocuments(query);
      const totalPages = Math.ceil(tot / perPage);
      res.render('mainTable', {lastModified:lastmodified,lt,gt,year,perPage,total:tot,cve, totalPages, currentPage: page,formatDate:formatDate});
    } catch (error) { 
        console.error("Error:", error); 
}});

app.get("/idResult", async (req, res) => {
    const id = req.query.SearchId;
    const perpage= 10;
    const query={
        "_id":{$regex:id}
    };
   const cve = await myColl.find(query).limit(10).toArray(); 
    let tot = await myColl.countDocuments(query);
        const totalPages = Math.ceil(tot / perpage);
    res.render('mainTable', {cve, total: tot, totalPages: totalPages,perPage:10,year:"", 
    currentPage: 1, formatDate: formatDate,gt:0,lt:10,lastModified:-1});             
});

app.get("/cves/list/:cveid", async (req, res) => {
    const id = req.params.cveid;
    const cve = await myColl.findOne({_id: id});
    
    if (!cve) {
        console.log(`CVE with ID ${id} not found`);
        return res.status(404).send('CVE not found');
    }
    
    let accessVector, accessComplexity, authentication, confidentialityImpact, integrityImpact, availabilityImpact, desc, Severity, score, vectorString, exploitabilityScore, impactScore, nodes;
    let criteriaArray = [], matchCriteriaIdArray = [], vulnerableArray = [], cpeLength = 0;
    
    if (cve.metrics && cve.metrics.cvssMetricV2 && cve.metrics.cvssMetricV2[0] && cve.metrics.cvssMetricV2[0].cvssData) {
        const metric = cve.metrics.cvssMetricV2[0].cvssData;
        accessVector = metric.accessVector;
        accessComplexity = metric.accessComplexity;
        authentication = metric.authentication;
        confidentialityImpact = metric.confidentialityImpact;
        integrityImpact = metric.integrityImpact;
        availabilityImpact = metric.availabilityImpact;
        desc = cve.descriptions[0].value;
        Severity = cve.metrics.cvssMetricV2[0].baseSeverity;
        score = metric.baseScore;
        vectorString = metric.vectorString;
        exploitabilityScore = cve.metrics.cvssMetricV2[0].exploitabilityScore;
        impactScore = cve.metrics.cvssMetricV2[0].impactScore;
        if(cve.configurations){
            nodes = cve.configurations[0].nodes;
        }
       
    } else if (cve.metrics && cve.metrics.cvssMetricV31 && cve.metrics.cvssMetricV31[0] && cve.metrics.cvssMetricV31[0].cvssData) {
        const metric = cve.metrics.cvssMetricV31[0].cvssData;
        accessVector = metric.attackVector;
        accessComplexity = metric.attackComplexity;
        authentication = metric.privilegesRequired;
        confidentialityImpact = metric.confidentialityImpact;
        integrityImpact = metric.integrityImpact;
        availabilityImpact = metric.availabilityImpact;
        desc = cve.descriptions[0].value;
        Severity = metric.baseSeverity;
        score = metric.baseScore;
        vectorString = metric.vectorString;
        exploitabilityScore = cve.metrics.cvssMetricV31[0].exploitabilityScore;
        impactScore = cve.metrics.cvssMetricV31[0].impactScore;
        if(cve.configurations){
            nodes = cve.configurations[0].nodes;
        }
    }

    if (nodes) {
        for (let i = 0; i < nodes.length; i++) {
            let cpeMatches = nodes[i].cpeMatch;
            for (let j = 0; j < cpeMatches.length; j++) {
                criteriaArray.push(cpeMatches[j].criteria);
                matchCriteriaIdArray.push(cpeMatches[j].matchCriteriaId);
                vulnerableArray.push(cpeMatches[j].vulnerable);
            }
        }
        cpeLength = criteriaArray.length;
    }
    
    res.render('subTable', { id, accessVector, accessComplexity, authentication, confidentialityImpact, integrityImpact, availabilityImpact, desc, Severity, score, vectorString, exploitabilityScore, impactScore, criteriaArray, matchCriteriaIdArray, vulnerableArray, cpeLength });
});











app.listen(3000, () => {
    console.log("Server started at " + 3000);
});

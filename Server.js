const express = require('express');
const mongoose = require('mongoose');
const app = express();
const ejs = require('ejs');
const bodyParser = require('body-parser');

app.use(express.static('public'));
app.set('view engine', 'ejs');

const uri = "mongodb://localhost:27017/Securin";
mongoose.connect(uri, { useNewUrlParser: true, useUnifiedTopology: true });


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
        const totalCount = await mongoose.connection.db.collection('Secure').countDocuments();
        // const totalPages = Math.ceil(totalCount / perPage);
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
       if(lastmodified==-1){ cve = await mongoose.connection.db.collection('Secure').find(query).sort({published:1}).skip(offset).limit(perPage).toArray();
       }
       else{
         cve = await mongoose.connection.db.collection('Secure').find(query).sort({lastModified:-1}).skip(offset).limit(lastmodified).toArray();
       }
       
      let tot = await mongoose.connection.db.collection('Secure').countDocuments(query);
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
   
    const cve = await mongoose.connection.db.collection('Secure')
        .find(query)
        .limit(10)
        .toArray(); 
   
        let tot = await mongoose.connection.db.collection('Secure').countDocuments(query);
        const totalPages = Math.ceil(tot / perpage);
    res.render('mainTable', {cve, total: tot, totalPages: totalPages,perPage:10,year:"", currentPage: 1, formatDate: formatDate,gt:0,lt:10,lastModified:-1});             
});

app.get("/cves/list/:cveid", async (req, res) => {
    const id = req.params.cveid;
    const cve = await mongoose.connection.db.collection('Secure')
        .find({_id: id})
        .toArray(); 
    if (cve[0] && cve[0].metrics && cve[0].metrics.cvssMetricV2 && cve[0].metrics.cvssMetricV2[0] && cve[0].metrics.cvssMetricV2[0].cvssData) {
        let accessVector = cve[0].metrics.cvssMetricV2[0].cvssData.accessVector;
        let accessComplexity = cve[0].metrics.cvssMetricV2[0].cvssData.accessComplexity;
        let authentication = cve[0].metrics.cvssMetricV2[0].cvssData.authentication;
        let confidentialityImpact = cve[0].metrics.cvssMetricV2[0].cvssData.confidentialityImpact;
        let integrityImpact = cve[0].metrics.cvssMetricV2[0].cvssData.integrityImpact;
        let availabilityImpact = cve[0].metrics.cvssMetricV2[0].cvssData.availabilityImpact;
        let desc = cve[0].descriptions[0].value;
        let Severity = cve[0].metrics.cvssMetricV2[0].baseSeverity;
        let score = cve[0].metrics.cvssMetricV2[0].cvssData.baseScore;
        let vectorString = cve[0].metrics.cvssMetricV2[0].cvssData.vectorString;
        let  = cve[0].metrics.cvssMetricV2[0].baseSeverity;
        let exploitabilityScore = cve[0].metrics.cvssMetricV2[0].exploitabilityScore;
        let impactScore = cve[0].metrics.cvssMetricV2[0].impactScore;
        let nodes = cve[0].configurations[0].nodes;
        let criteriaArray = [];
        let matchCriteriaIdArray = [];
        let vulnerableArray = [];
        
        for (let i = 0; i < nodes.length; i++) {
          let cpeMatches = nodes[i].cpeMatch;
          for (let j = 0; j < cpeMatches.length; j++) {
            criteriaArray.push(cpeMatches[j].criteria);
            matchCriteriaIdArray.push(cpeMatches[j].matchCriteriaId);
            vulnerableArray.push(cpeMatches[j].vulnerable);
          }
        }
        let cpeLength = criteriaArray.length;
        console.log(cpeLength);
        
        // console.log(`Criteria Array: ${criteriaArray}`);
        // console.log(`Match Criteria ID Array: ${matchCriteriaIdArray}`);
        // console.log(`Vulnerable Array: ${vulnerableArray}`);
        
        res.render('subTable', {id,accessVector,accessComplexity,authentication,confidentialityImpact,integrityImpact,availabilityImpact,desc,Severity,score,vectorString,exploitabilityScore,impactScore,criteriaArray, matchCriteriaIdArray,vulnerableArray,cpeLength});

        
       
    } else {
        console.log('baseScore does not exist');
    }
   
   
});











app.listen(3000, () => {
    console.log("Server started at " + 3000);
});

const mongoose = require("mongoose");
var db = mongoose.connection;

const { calculateLevel } = require("./siteAlgorithms");

// input a string (the question ID), returns question entry
function getQuestion(Ques, id) {
    return Ques.findById(id).exec();
}

// input a rating range (as floor and ceiling values), returns a range of questions
async function getQuestions (Ques, ratingFloor, ratingCeiling, subject, units) {
    const gotQ = Ques.find({subject: [subject], rating: { $gte: ratingFloor, $lte: ratingCeiling } });
    var tempQ = await gotQ.exec();
    for(i = 0; i < tempQ.length; i++){
        const found = units.some(r => tempQ[i].units.includes(r));
        if(!found){
            tempQ.splice(i, 1);
            i--;
        }
    }
    return tempQ;
}

// return rating of the user logged in right now
function getRating (subject, req) {
    return req.user.rating[subject.toLowerCase()];
}

// set the rating of the user logged in right now
function setRating (subject, newRating, req) {
    req.user.rating[subject.toLowerCase()] = newRating;
    db.collection("users").findOneAndUpdate({ username: req.user.username }, { $set: { rating: req.user.rating } });
}

// modify the correct/wrong counter for users, and the pass/fail counter for questions, as well as tag collector tags

function updateAll (req, question, correct) {
    updateCounters(req, question, correct);
    updateTracker(req, question);
    updateLastAnswered(req, question);
    addExperience(req, correct ? question.rating : Math.ceil(question.rating/2));
}
function updateCounters (req, question, correct) {

    // configure general counters
    if (correct) {
        // update counters
        req.user.stats.correct++;
        question.stats.pass++;
        // update tag collector
        question.tags.forEach((tag) => {
            if(!req.user.stats.collectedTags.includes(tag)) {
                req.user.stats.collectedTags.push(tag);
            }
        });
    } else if (!correct) {
        req.user.stats.wrong++;
        question.stats.fail++;
    }

    // unit-specific counters
    if(!req.user.stats.units) {
        req.user.stats.units = {};
    }
    question.units.forEach((unit) => {

        if(!req.user.stats.units["" + unit]) {
            req.user.stats.units["" + unit] = {
                correct: 0,
                wrong: 0,
                highestQRating: 100,
                highestQCorrectRating: 100,
                pastResults: [],
                pastRatings: [],
                lastTouched: ""
            };
        }

        // temporary tracker
        let tempUnit = req.user.stats.units["" + unit];

        if(question.rating > tempUnit.highestQRating) {
            tempUnit.highestQRating = question.rating;
        }

        if(correct) {
            tempUnit.correct++;
            tempUnit.pastResults.push(1);
            if(question.rating > tempUnit.highestQCorrectRating) {
                tempUnit.highestQCorrectRating = question.rating;
            }
        } else {
            tempUnit.wrong++;
            tempUnit.pastResults.push(-1);
        }

        tempUnit.pastRatings.push(question.rating);

        while(tempUnit.pastRatings.length > 15) {
            tempUnit.pastRatings.shift();
        }
        while(tempUnit.pastResults.length > 15) {
            tempUnit.pastResults.shift();
        }

        tempUnit.lastTouched = new Date().toISOString().split('T')[0];

        req.user.stats.units["" + unit] = tempUnit;

    });

    db.collection("users").findOneAndUpdate({ username: req.user.username }, { $set: { stats: req.user.stats } });
    db.collection("questions").findOneAndUpdate({ _id: question._id }, { $set: { stats: { pass: question.stats.pass, fail: question.stats.fail } } });
}
function updateTracker (req, question) {
    // update rating tracker
    var tracker;
    if(req.user.stats.ratingTracker === undefined) {
        req.user.stats.ratingTracker = {};
    }
    try {
        // try to update the tracker
        tracker = req.user.stats.ratingTracker[question.subject[0].toLowerCase()];
        tracker.push(req.user.rating[question.subject[0].toLowerCase()]);
        while(tracker.length > 20) {
            tracker.shift();
        }
    } catch(err) {
        // tracker doesn't exist (yet), so create one!
        tracker = [req.user.rating[question.subject[0].toLowerCase()]];
        req.user.stats.ratingTracker[question.subject[0].toLowerCase()];
    }
    req.user.stats.ratingTracker[question.subject[0].toLowerCase()] = tracker;
    db.collection("users").findOneAndUpdate({ username: req.user.username }, { $set: { stats: req.user.stats } });
}
function updateLastAnswered (req, question) {
    // updated "last answered" field with question ID
    req.user.stats.lastAnswered = question._id;
    db.collection("users").findOneAndUpdate({ username: req.user.username }, { $set: { stats: req.user.stats } });
}
function addExperience(req, amount) {
    // add experience points to user
    if(req.user.stats.experience) {
        req.user.stats.experience += amount;
    } else {
        req.user.stats.experience = amount;
    }
    db.collection("users").findOneAndUpdate({ username: req.user.username }, { $set: { stats: req.user.stats } });
}

async function incrementSolveCounter(SiteData, subject, correct) {
    let data = await SiteData.findOne({ tag: "QUESTIONS" }).exec();
    let counts = data.data;
    counts.attempts[subject] += 1;
    if(correct) {
        counts.solves[subject] += 1;
    }
    db.collection("sitedatas").findOneAndUpdate({ tag: "QUESTIONS" }, { $set: { data: counts } });
}

// update "to answer" queue field in user db
function updateQuestionQueue (req, subject, id) {
    req.user.stats.toAnswer[subject.toLowerCase()] = id;
    db.collection("users").findOneAndUpdate({ username: req.user.username }, { $set: { stats: req.user.stats } });
}
function clearQuestionQueue (req, subject) {
    req.user.stats.toAnswer[subject.toLowerCase()] = "";
    db.collection("users").findOneAndUpdate({ username: req.user.username }, { $set: { stats: req.user.stats } });
}

// things to update when skipping question
async function skipQuestionUpdates(Ques, req, subject, id) {

    // deduct 8 rating for skipping
    var originalRating = getRating(subject, req);
    var deduction = originalRating > 8 ? originalRating-8 : 0;
    setRating(subject, deduction, req);

    // update rating tracker
    let q = await getQuestion(Ques, id);
    updateTracker(req, q);

    // add +1 wrong for question and give question one rating
    q.rating += 1;
    q.stats.fail += 1;
    db.collection("questions").findOneAndUpdate({ _id: q._id }, { $set: { stats: q.stats, rating: q.rating } });
}

// set question rating
function setQRating (antsy, newQRate) {
    antsy.rating = newQRate;
    db.collection("questions").findOneAndUpdate({ _id: antsy._id }, { $set: {rating: antsy.rating} });
}

// generate a leaderboard for a certain subject; count is the number of people on board
async function generateLeaderboard (User, count) {

    // NOTE: change the $gte to a higher number once we get more users
    let physics = await User.find({ "rating.physics": { $gte: 1000 } }).sort({ "rating.physics": -1 }).limit(count).exec();
    let chem = await User.find({ "rating.chemistry": { $gte: 1000 } }).sort({ "rating.chemistry": -1 }).limit(count).exec();
    let bio = await User.find({ "rating.biology": { $gte: 1000 } }).sort({ "rating.biology": -1 }).limit(count).exec();

    let rush = await User.find({ "stats.rush.highscore": { $gte: 10 } }).sort({ "stats.rush.highscore": -1 }).limit(count).exec();
    let experience = await User.find({ "stats.experience": { $gte: 10000 } }).sort({ "stats.experience": -1 }).limit(count).exec();

    experience = experience.map(user => {
        return {
            level: calculateLevel(user.stats.experience),
            experience: user.stats.experience,
            ign: user.ign
        }
    });

    return { physics, chem, bio, rush, experience };

}

async function getDailyQuestion(Daily, Ques) {

    // attempt to get daily object
    const date = await new Date().toISOString().split('T')[0];
    let question = await Daily.findOne({ date }).exec();

    if(question) {

        // if daily object exists
        let content = await Ques.findById(question.question).exec();

        return content;
    } else {

        // if daily object does not exist, create a new one
        const questions = await Ques.find({ rating: { $gte: 2500, $lte: 4000 } }).exec();
        const selection = await questions[Math.floor(Math.random() * questions.length)];

        // Manually set daily question date, maybe the defaults are weird?
        let question = await new Daily({
            question: selection._id,
            date: date
        })

        await question.save();

        return selection;
    }
}

async function getSiteData(User, Ques, SiteData) {

    let userCount = await User.estimatedDocumentCount({});
    let questionCount = await Ques.estimatedDocumentCount({});

    let tagCounter = () => {
        let { tags } = require('../constants/tags');
        let counter = 0;
        Object.entries(tags).forEach((subjEntry) => {
            Object.entries(subjEntry[1]).forEach((typeEntry) => {
                Object.entries(typeEntry[1]).forEach((tagEntry) => {
                    counter += 1;
                })
            });
        });
        return counter;
    }

    let tagCount = await tagCounter();
    let proficientCount = await User.countDocuments({
        // any users with at least 1 rating above 2500
        $or: [
            { 'rating.physics': { $gte: 2500 } },
            { 'rating.chemistry': { $gte: 2500 } },
            { 'rating.biology': { $gte: 2500 } }
        ]
    });

    let totalQuestionData = await SiteData.findOne({ tag: "QUESTIONS" }).exec();
    let totalSolves = totalQuestionData.data.solves;
    let totalAttempts = totalQuestionData.data.attempts;

    let siteData = {
        userCount,
        questionCount,
        tagCount,
        proficientCount,
        totalSolves,
        totalAttempts
    }

    return siteData;
}

// returns 10 most recent announcements
async function getAnnouncements(SiteData, numberToFetch) {

    let announcements = await SiteData.findOne({ tag: "ANNOUNCEMENTS" }).exec();
    let siteAnnouncements = announcements.data.site;

    let recentAnnouncements = siteAnnouncements.reverse().slice(0, numberToFetch);

    return recentAnnouncements;
}

// updates problem rush stats
async function updateRushStats(user, score) {

    if(!user.stats.rush) {
        user.stats.rush = {
            attempts: 0,
            highscore: 0
        }
    }

    if(!user.stats.rush.highscore) {
        user.stats.rush.highscore = 0;
    }

    if(!user.stats.rush.attempts) {
        user.stats.rush.attempts = 0;
    }

    user.stats.rush.attempts += 1;

    if(user.stats.rush.highscore < score) {

        user.stats.rush.highscore = score;
    }

    db.collection("users").findOneAndUpdate({ username: user.username }, { $set: { stats: user.stats } });
}

async function querySite(search, User, Ques, SiteData) {

    results = [];
    search = search.trim();

    let possibleID = 0;
    try {
        possibleID = mongoose.Types.ObjectId(search);
    } catch(err) {
        possibleID = mongoose.Types.ObjectId('000000000000000000000000');
    }

    // find matches
    let userMatches = await User.find({
        $or: [
            { _id: possibleID },
            { ign: { $regex: new RegExp(search), $options: 'ix' }},
            { "profile.name": { $regex: new RegExp(search), $options: 'i' }}
        ]
    }).exec();

    let questionMatches = await Ques.find({
        $or: [
            { _id: possibleID },
            { question: { $regex: new RegExp(search), $options: 'i' }},
            { choices: { $regex: new RegExp(search), $options: 'i' }},
            { tags: search.toUpperCase() },
            { answer_ex: { $regex: new RegExp(search), $options: 'i' }},
            { ext_source: search },
            { subject: { $regex: new RegExp(search), $options: 'ix' }},
            { units: { $regex: new RegExp(search), $options: 'i' }}
        ]
    }).sort({ rating: -1}).exec();

    // load matches into results
    questionMatches.forEach((question) => {
        if(search.toUpperCase() == question.question.toUpperCase() || question.tags.includes(search.toUpperCase()) || question._id.toString() == search) {
            results.unshift({
                exactMatch: true,
                type: "QUESTION",
                id: question._id,
                title: question.subject[0] + " (" + question.rating + " Rated)",
                preview: "ID: " + question._id + ", Relevant Tags: " + question.tags.join(" ")
            });
        } else {
            results.push({
                exactMatch: false,
                type: "QUESTION",
                id: question._id,
                title: question.subject[0] + " (" + question.rating + " Rated)",
                preview: "ID: " + question._id + ", Relevant Tags: " + question.tags.join(" ")
            });
        }
    });

    userMatches.forEach((user) => {

        if(search.toUpperCase() == user.ign.toUpperCase() || user._id.toString() == search) {
            results.unshift({
                exactMatch: true,
                type: "USER",
                id: user.ign,
                title: user.ign + (user.profile.name ? " (" + user.profile.name + ")" : ""),
                preview: (user.profile.bio ? user.profile.bio + " " : "") + "Experience: " + user.stats.experience + ", "
                    + user.stats.collectedTags.length + " tags collected"
            });
        } else {
            results.push({
                exactMatch: false,
                type: "USER",
                id: user.ign,
                title: user.ign + (user.profile.name ? " (" + user.profile.name + ")" : ""),
                preview: (user.profile.bio ? user.profile.bio + ", " : "") + "Experience: " + user.stats.experience + ", "
                    + user.stats.collectedTags.length + " tags collected"
            });
        }
    });

    return results;
}

async function updateFields(){ //replace the parameters as needed for different purposes
    db.collection('users').updateMany({'age': {$exists: true}}, {$rename: {'age': 'yob'}});
}

module.exports = { getQuestion, getQuestions, getRating, setRating, setQRating, updateCounters, updateTracker, updateLastAnswered, updateAll, updateQuestionQueue, addExperience,
    clearQuestionQueue, skipQuestionUpdates, generateLeaderboard, getDailyQuestion, getSiteData, incrementSolveCounter, getAnnouncements, updateRushStats, querySite, updateFields };


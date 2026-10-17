const {
  onRequest
} = require("firebase-functions/v2/https");

const {
  initializeApp
} = require("firebase-admin/app");

const {
  getAuth
} = require("firebase-admin/auth");

const {
  getFirestore,
  FieldValue
} = require("firebase-admin/firestore");

const {
  createCampusApp
} = require("./campus-api");

initializeApp();

exports.campusApi = onRequest(
  {
    region: "asia-east1",
    maxInstances: 5,
    concurrency: 1,
    timeoutSeconds: 60,
    invoker: "public"
  },
  createCampusApp({
    auth: getAuth(),
    db: getFirestore(),
    timestamp: () => FieldValue.serverTimestamp()
  })
);
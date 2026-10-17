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


async function main() {
  const uid = process.argv[2];
  const name = process.argv[3];

  if (
    !uid ||
    !name ||
    uid.length > 128 ||
    uid.includes("/") ||
    name.length > 100
  ) {
    throw new Error(
      'Usage: npm run bootstrap-admin -- YOUR_AUTH_UID "Your Full Name"'
    );
  }

  initializeApp({
    projectId: "smart-campus-9aafa"
  });

  const user = await getAuth().getUser(uid);

  if (user.disabled) {
    throw new Error(
      "This Firebase Authentication account is disabled."
    );
  }

  if (!user.email) {
    throw new Error(
      "Choose an account with an email address."
    );
  }

  const db = getFirestore();

  const profileRef = db
    .collection("users")
    .doc(uid);

  const snapshot = await profileRef.get();

  if (
    snapshot.exists &&
    snapshot.data().role !== "admin"
  ) {
    throw new Error(
      "This account already has another campus role. " +
      "Create a separate Firebase Authentication account for Admin."
    );
  }

  const profile = {
    name: name.trim(),
    email: user.email,
    role: "admin",
    active: true,
    updated_at: FieldValue.serverTimestamp()
  };

  if (!snapshot.exists) {
    profile.created_at =
      FieldValue.serverTimestamp();
  }

  await profileRef.set(
    profile,
    { merge: true }
  );

  console.log("Admin profile saved successfully.");
  console.log("Email:", user.email);
  console.log(
    "Login: http://127.0.0.1:5003/login.html?role=admin"
  );
}


main().catch(error => {
  console.error(
    "Could not create Admin profile:",
    error.message
  );

  process.exitCode = 1;
});
// TODO: implement create/get/destroy around an in-memory Map.
// Store opaque session id -> { userId, expiresAt }, never credentials.
// Remove expired sessions during reads.

const sessions = new Map();

// Create a server-side session.
function create({ id, userId, expiresAt }) {
  sessions.set(id, {
    userId,
    expiresAt
  });
}

// Get a session by ID.
// Remove it if it has expired.
function get(id) {
  const session = sessions.get(id);

  if (!session) {
    return null;
  }

  if (session.expiresAt <= Date.now()) {
    sessions.delete(id);
    return null;
  }

  return session;
}

// Destroy a session.
function destroy(id) {
  sessions.delete(id);
}

module.exports = {
  create,
  get,
  destroy
};

module.exports = (req, res) => {
  const { user_id, value, token } = req.query;
  const expectedToken = "6a55a7ef-5f3a-42aa-a7b8-d939ad9a3037";
  
  if (token !== expectedToken) {
    return res.status(401).json({ error: "Unauthorized: Invalid token" });
  }

  return res.status(200).json({ status: "success", message: "Postback received successfully" });
};
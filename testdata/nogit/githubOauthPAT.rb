access_tokens = [
    'gho_123456789012345678901234567890123456',
    'gho_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCD',
    'gho_987654321098765432109876543210987654',
    'gho_EFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEF'
    'ghz_EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE'
    'ghb_FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'
]

pattern = /gho_[0-9a-zA-Z]{36}/

access_tokens.each_with_index do |token, i|
  if pattern.match?(token)
    puts "Matched Access Token #{i}: #{token}"
  else
    puts "No match for Access Token #{i}: #{token}"
  end
end

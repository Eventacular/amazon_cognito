defmodule AmazonCognito do
  def get_open_id_token_for_developer_identity(key, secret, region, identity_pool_id, logins, identity_id \\ nil) do
		time = Timex.Date.now
		body = %{"IdentityPoolId": identity_pool_id, "Logins": logins}
		if identity_id != nil do
			body = Dict.put(body, "IdentityId", identity_id)
		end
		body = body |> Poison.encode!
		headers = HashDict.new |>
			Dict.put("X-Amz-Target", "AWSCognitoIdentityService.GetOpenIdTokenForDeveloperIdentity") |>
			Dict.put("X-Amz-Date", Timex.DateFormat.format!(time, "%Y%m%dT%H%M%SZ", :strftime)) |>
			Dict.put("User-Agent", "Eventacular") |>
			Dict.put("x-amz-content-sha256", "") |>
			Dict.put("Content-Type", "application/x-amz-json-1.1")
		signature = AWSAuth.sign_authorization_header(
			key,
			secret,
			"POST",
			"https://cognito-identity.us-east-1.amazonaws.com/",
			region,
			"cognito-identity",
			headers,
			body,
			time
		)
		headers = headers |> Dict.put("Authorization", signature)
		result = HTTPotion.post("https://cognito-identity.us-east-1.amazonaws.com", body: body, headers: headers)
		result.body |> Poison.decode!
  end
end

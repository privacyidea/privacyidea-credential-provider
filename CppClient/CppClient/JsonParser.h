#pragma once
#include "PIResponse.h"
#include "OfflineData.h"
#include <string>
#include <vector>
#include <winerror.h>

#define PI_JSON_PARSE_ERROR							((HRESULT)0x88809031)
#define JSON_DUMP_INDENTATION 4

class JsonParser
{
public:
	/// <summary>
	/// Parse the contents of a privacyIDEA response into an object.
	/// </summary>
	/// <param name="serverResponse"></param>
	/// <param name="responseObj"></param>
	/// <returns>
	/// S_OK success, 
	/// PI_JSON_PARSE_ERROR if the input is malformed or a required field is missing
	/// </returns>
	HRESULT ParsePIResponse(std::string serverResponse, PIResponse &responseObj);

	/// <summary>
	/// 
	/// </summary>
	/// <param name="input"></param>
	/// <returns></returns>
	std::vector<OfflineData> ParseResponseForOfflineData(std::string input);

	/// <summary>
	/// The format of the saved file differs from the server response. Therefore it should be parsed with this method.
	/// </summary>
	/// <param name="input"></param>
	/// <returns></returns>
	std::vector<OfflineData> ParseFileContentsForOfflineData(std::string input);

	HRESULT ParseOfflineDataItemFromString(std::string input, OfflineData& data);

	std::string OfflineDataToString(std::vector<OfflineData> data);

	bool ParsePollTransaction(std::string input);

	HRESULT ParseRefillResponse(const std::string& in, const std::string& username, OfflineData& data);

	// Return the input json with indentation of 4. If the input is not a valid json it is returned as is.
	static std::string PrettyFormatJson(std::string input);

};


import Foundation

/// Default `HTTPDataClient` backed by `URLSession` with an ephemeral,
/// short-timeout configuration suited to quick diagnostic calls.
struct URLSessionDataClient: HTTPDataClient {
    func data(from url: URL) async throws -> Data {
        do {
            let (data, response) = try await UnifiedNetworkInterface.httpData(
                from: url, operation: "http-data", target: url.host ?? url.absoluteString
            )
            if let http = response as? HTTPURLResponse,
               !(200..<300).contains(http.statusCode) {
                throw NetworkServiceError.badStatus(http.statusCode)
            }
            return data
        } catch let error as NetworkServiceError {
            throw error
        } catch let error as URLError where error.code == .notConnectedToInternet
            || error.code == .networkConnectionLost
            || error.code == .dataNotAllowed {
            throw NetworkServiceError.offline
        }
    }
}

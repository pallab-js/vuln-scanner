import Testing
import Foundation
import NIOCore
import NIOHTTP1
import Core
@testable import API

@Test func restServerLifecycleAndAuth() async throws {
    let server = RESTServer.shared

    // Start without auth
    server.apiKey = ""
    server.port = 8183
    #expect(server.isRunning == false)
    try server.start(host: "127.0.0.1")
    #expect(server.isRunning)
    defer { server.stop(); server.apiKey = "" }

    // GET /health → 200
    do {
        let url = URL(string: "http://127.0.0.1:8183/health")!
        let (data, response) = try await URLSession.shared.data(from: url)
        let httpResponse = try #require(response as? HTTPURLResponse)
        #expect(httpResponse.statusCode == 200)
        let body = try JSONDecoder().decode(HealthDTO.self, from: data)
        #expect(body.status == "ok")
    }

    // GET /api/v1/health (prefixed) → 200
    do {
        let url = URL(string: "http://127.0.0.1:8183/api/v1/health")!
        let (_, response) = try await URLSession.shared.data(from: url)
        let httpResponse = try #require(response as? HTTPURLResponse)
        #expect(httpResponse.statusCode == 200)
    }

    // GET unknown route → 404
    do {
        let url = URL(string: "http://127.0.0.1:8183/api/nonexistent")!
        let (_, response) = try await URLSession.shared.data(from: url)
        let httpResponse = try #require(response as? HTTPURLResponse)
        #expect(httpResponse.statusCode == 404)
    }
}

@Test func restServerAuth() async throws {
    let server = RESTServer.shared
    server.apiKey = "secret123"
    server.port = 8184

    try server.start(host: "127.0.0.1")
    defer { server.stop(); server.apiKey = "" }

    // Wrong key → 401
    var req = URLRequest(url: URL(string: "http://127.0.0.1:8184/health")!)
    req.setValue("Bearer wrong-key", forHTTPHeaderField: "Authorization")
    let (_, badResp) = try await URLSession.shared.data(for: req)
    let badHttp = try #require(badResp as? HTTPURLResponse)
    #expect(badHttp.statusCode == 401)

    // Correct key → 200
    var okReq = URLRequest(url: URL(string: "http://127.0.0.1:8184/health")!)
    okReq.setValue("Bearer secret123", forHTTPHeaderField: "Authorization")
    let (_, okResp) = try await URLSession.shared.data(for: okReq)
    let okHttp = try #require(okResp as? HTTPURLResponse)
    #expect(okHttp.statusCode == 200)
}

private struct HealthDTO: Decodable {
    let status: String
    let version: Int
}

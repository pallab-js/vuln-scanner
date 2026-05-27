import Testing
import Foundation
import NIOCore
import NIOHTTP1
import Core
@testable import API

@Test func restServerLifecycleAndEndpoints() async throws {
    let server = RESTServer.shared
    server.apiKey = ""

    #expect(server.isRunning == false)

    server.port = 8181
    try server.start(host: "127.0.0.1")
    #expect(server.isRunning)

    defer { server.stop(); server.apiKey = "" }

    do {
        let url = URL(string: "http://127.0.0.1:8181/api/status")!
        let (data, response) = try await URLSession.shared.data(from: url)
        let httpResponse = try #require(response as? HTTPURLResponse)
        #expect(httpResponse.statusCode == 200)
        let body = try JSONDecoder().decode([String: String].self, from: data)
        #expect(body["status"] == "ok")
    }

    do {
        let url = URL(string: "http://127.0.0.1:8181/health")!
        let (data, response) = try await URLSession.shared.data(from: url)
        let httpResponse = try #require(response as? HTTPURLResponse)
        #expect(httpResponse.statusCode == 200)
        let body = try JSONDecoder().decode([String: String].self, from: data)
        #expect(body["status"] == "ok")
    }

    do {
        let url = URL(string: "http://127.0.0.1:8181/api/nonexistent")!
        let (_, response) = try await URLSession.shared.data(from: url)
        let httpResponse = try #require(response as? HTTPURLResponse)
        #expect(httpResponse.statusCode == 404)
    }
}

@Test func restServerAuth() async throws {
    let server = RESTServer.shared
    server.apiKey = "secret123"

    server.port = 8182
    try server.start(host: "127.0.0.1")

    defer { server.stop(); server.apiKey = "" }

    var req = URLRequest(url: URL(string: "http://127.0.0.1:8182/api/status")!)
    req.setValue("Bearer wrong-key", forHTTPHeaderField: "Authorization")
    let (_, response) = try await URLSession.shared.data(for: req)
    let httpResponse = try #require(response as? HTTPURLResponse)
    #expect(httpResponse.statusCode == 401)

    var reqOk = URLRequest(url: URL(string: "http://127.0.0.1:8182/api/status")!)
    reqOk.setValue("Bearer secret123", forHTTPHeaderField: "Authorization")
    let (_, respOk) = try await URLSession.shared.data(for: reqOk)
    let httpRespOk = try #require(respOk as? HTTPURLResponse)
    #expect(httpRespOk.statusCode == 200)
}

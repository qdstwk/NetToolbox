import SwiftUI
import Observation
#if canImport(Darwin)
import Darwin
#endif

@MainActor
@Observable
final class NSLookupViewModel {
    enum Output: Equatable {
        case idle, loading
        case forward([String])
        case reverse(String)
        case notFound
    }

    var query = ""
    private(set) var output: Output = .idle

    var isReverse: Bool { InputClassifier.isIPv4(query.trimmingCharacters(in: .whitespaces)) }

    func lookup() async {
        let target = query.trimmingCharacters(in: .whitespaces)
        guard !target.isEmpty else { output = .idle; return }
        output = .loading

        let lease: UnifiedNetworkInterface.Lease
        do { lease = try await UnifiedNetworkInterface.claim(operation: "nslookup", target: target) }
        catch { output = .notFound; return }
        let cancellation = NetworkCancellationHandle()
        await UnifiedNetworkInterface.registerCancellation(for: lease) { cancellation.cancel() }
        let dns = UDPDNSResolver()

        if isReverse {
            let reversed = target.split(separator: ".").reversed().joined(separator: ".") + ".in-addr.arpa"
            let records = (try? await dns.resolve(name: reversed, type: .ptr, server: "1.1.1.1", cancellation: cancellation)) ?? []
            output = records.first.map { .reverse($0.value) } ?? .notFound
        } else {
            let a = (try? await dns.resolve(name: target, type: .a, server: "1.1.1.1", cancellation: cancellation)) ?? []
            let aaaa = cancellation.isCancelled ? [] : ((try? await dns.resolve(name: target, type: .aaaa, server: "1.1.1.1", cancellation: cancellation)) ?? [])
            let addresses = (a + aaaa).map(\.value)
            output = addresses.isEmpty ? .notFound : .forward(addresses)
        }
        await UnifiedNetworkInterface.release(lease)
    }
}

struct NSLookupTool: NetworkTool {
    let id = "nslookup"
    let titleKey = L10n("tool.nslookup.title")
    let subtitleKey = L10n("tool.nslookup.subtitle")
    let systemImage = "magnifyingglass.circle"
    let category: ToolCategory = .dns

    func makeView() -> AnyView { AnyView(NSLookupView()) }
}

@MainActor
struct NSLookupView: View {
    @Environment(\.theme) private var theme
    @State private var viewModel = NSLookupViewModel()

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Spacing.lg) {
                inputSection
                outputSection
            }
            .padding(Spacing.xl)
            .frame(maxWidth: 900)
            .frame(maxWidth: .infinity)
        }
        .background(theme.background)
        .navigationTitle(Text(L10n("tool.nslookup.title")))
        .navigationBarTitleDisplayMode(.large)
    }

    private var inputSection: some View {
        SectionCard(title: L10n("nslookup.input.title"), systemImage: "magnifyingglass") {
            HStack(spacing: Spacing.sm) {
                TextField(L10nString("nslookup.input.placeholder"), text: $viewModel.query)
                    .textFieldStyle(.roundedBorder)
                    .font(AppTypography.monoBody)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                    .keyboardType(.URL)
                    .environment(\.layoutDirection, .leftToRight)
                    .onSubmit { Task { await viewModel.lookup() } }
                SavedHostMenu(host: $viewModel.query)
            }

            HStack {
                Button {
                    Task { await viewModel.lookup() }
                } label: {
                    Label(L10nString("host.action.resolve"), systemImage: "arrow.right.circle.fill")
                        .font(AppTypography.headline)
                }
                .buttonStyle(.borderedProminent)
                Spacer()
                Text(viewModel.isReverse ? L10n("nslookup.mode.reverse") : L10n("nslookup.mode.forward"))
                    .font(AppTypography.monoCaption)
                    .foregroundStyle(theme.textSecondary)
            }
        }
    }

    @ViewBuilder
    private var outputSection: some View {
        switch viewModel.output {
        case .idle:
            ContentUnavailableView {
                Label(L10nString("nslookup.empty.title"), systemImage: "magnifyingglass.circle")
            } description: {
                Text(L10n("nslookup.empty.description"))
            }
        case .loading:
            HStack(spacing: Spacing.md) {
                ProgressView()
                Text(L10n("common.loading")).foregroundStyle(theme.textSecondary)
            }
            .frame(maxWidth: .infinity)
        case .notFound:
            SectionCard(title: L10n("common.error"), systemImage: "exclamationmark.triangle.fill") {
                Text(L10n("host.notFound")).font(AppTypography.body).foregroundStyle(theme.danger)
            }
        case .forward(let addresses):
            SectionCard(title: L10n("nslookup.section.addresses"), systemImage: "list.bullet") {
                VStack(spacing: Spacing.sm) {
                    ForEach(addresses, id: \.self) { address in
                        HStack {
                            StatusBadge(kind: address.contains(":") ? .neutral : .info,
                                        text: address.contains(":") ? "IPv6" : "IPv4")
                            Spacer()
                            CopyableValue(value: address)
                        }
                    }
                }
            }
        case .reverse(let host):
            SectionCard(title: L10n("nslookup.section.hostname"), systemImage: "text.badge.checkmark") {
                HStack {
                    CopyableValue(value: host, font: AppTypography.monoBody)
                    Spacer()
                }
            }
        }
    }
}

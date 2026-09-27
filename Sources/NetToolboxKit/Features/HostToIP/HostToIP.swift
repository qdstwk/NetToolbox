import SwiftUI
import Observation
#if canImport(Darwin)
import Darwin
#endif

@MainActor
@Observable
final class HostToIPViewModel {
    enum Output: Equatable {
        case idle, loading
        case success([String])
        case failure
    }

    var host = ""
    private(set) var output: Output = .idle

    func resolve() async {
        let trimmed = host.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { output = .idle; return }
        output = .loading
        let lease: UnifiedNetworkInterface.Lease
        do { lease = try await UnifiedNetworkInterface.claim(operation: "host-resolve", target: trimmed) }
        catch { output = .failure; return }
        let cancellation = NetworkCancellationHandle()
        await UnifiedNetworkInterface.registerCancellation(for: lease) { cancellation.cancel() }
        let dns = UDPDNSResolver()
        let a = (try? await dns.resolve(name: trimmed, type: .a, server: "1.1.1.1", cancellation: cancellation)) ?? []
        let aaaa = cancellation.isCancelled ? [] : ((try? await dns.resolve(name: trimmed, type: .aaaa, server: "1.1.1.1", cancellation: cancellation)) ?? [])
        let addresses = (a + aaaa).map(\.value)
        await UnifiedNetworkInterface.release(lease)
        output = addresses.isEmpty ? .failure : .success(addresses)
    }
}

struct HostToIPTool: NetworkTool {
    let id = "host-to-ip"
    let titleKey = L10n("tool.host.title")
    let subtitleKey = L10n("tool.host.subtitle")
    let systemImage = "arrow.right.arrow.left"
    let category: ToolCategory = .diagnostics

    func makeView() -> AnyView { AnyView(HostToIPView()) }
}

@MainActor
struct HostToIPView: View {
    @Environment(\.theme) private var theme
    @State private var viewModel = HostToIPViewModel()

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
        .navigationTitle(Text(L10n("tool.host.title")))
        .navigationBarTitleDisplayMode(.large)
    }

    private var inputSection: some View {
        SectionCard(title: L10n("host.input.title"), systemImage: "arrow.right.arrow.left") {
            HStack(spacing: Spacing.sm) {
                TextField(L10nString("host.input.placeholder"), text: $viewModel.host)
                    .textFieldStyle(.roundedBorder)
                    .font(AppTypography.monoBody)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                    .keyboardType(.URL)
                    .environment(\.layoutDirection, .leftToRight)
                    .onSubmit { Task { await viewModel.resolve() } }
                SavedHostMenu(host: $viewModel.host)
            }

            Button {
                Task { await viewModel.resolve() }
            } label: {
                Label(L10nString("host.action.resolve"), systemImage: "arrow.right.circle.fill")
                    .font(AppTypography.headline)
            }
            .buttonStyle(.borderedProminent)
        }
    }

    @ViewBuilder
    private var outputSection: some View {
        switch viewModel.output {
        case .idle:
            ContentUnavailableView {
                Label(L10nString("host.empty.title"), systemImage: "arrow.right.arrow.left")
            } description: {
                Text(L10n("host.empty.description"))
            }
        case .loading:
            HStack(spacing: Spacing.md) {
                ProgressView()
                Text(L10n("common.loading")).foregroundStyle(theme.textSecondary)
            }
            .frame(maxWidth: .infinity)
        case .failure:
            SectionCard(title: L10n("common.error"), systemImage: "exclamationmark.triangle.fill") {
                Text(L10n("host.notFound")).font(AppTypography.body).foregroundStyle(theme.danger)
            }
        case .success(let addresses):
            SectionCard(title: L10n("host.section.addresses"), systemImage: "list.bullet") {
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
        }
    }
}

import SwiftUI

/// Saved-camera overview. Strict single-line network policy forbids
/// starting multiple RTSP sessions at once; grid cells are metadata-only.
@MainActor
struct CameraGridView: View {
    @Environment(\.theme) private var theme
    @Environment(\.dismiss) private var dismiss
    @Environment(CameraStore.self) private var store

    private let columns = [GridItem(.adaptive(minimum: 300), spacing: Spacing.md)]

    var body: some View {
        NavigationStack {
            ScrollView {
                if store.cameras.isEmpty {
                    Text(L10n("camera.empty"))
                        .font(AppTypography.footnote)
                        .foregroundStyle(theme.textSecondary)
                        .padding(Spacing.xl)
                } else {
                    LazyVGrid(columns: columns, spacing: Spacing.md) {
                        ForEach(store.cameras) { camera in
                            CameraGridCell(camera: camera)
                        }
                    }
                    .padding(Spacing.md)
                }
            }
            .background(theme.background)
            .navigationTitle(Text(L10n("camera.grid.title")))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button(L10nString("common.done")) { dismiss() }
                }
            }
        }
    }
}

@MainActor
private struct CameraGridCell: View {
    @Environment(\.theme) private var theme
    let camera: CameraStore.Camera

    @State private var session = CameraSession()

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.xs) {
            ZStack {
                Color.black
                Image(systemName: "video")
                    .font(.largeTitle)
                    .foregroundStyle(.white.opacity(0.7))
            }
            .aspectRatio(16.0 / 9.0, contentMode: .fit)
            .clipShape(RoundedRectangle(cornerRadius: CornerRadius.medium, style: .continuous))

            Text(camera.displayName)
                .font(AppTypography.caption)
                .foregroundStyle(theme.textSecondary)
                .lineLimit(1)
        }

    }

    @ViewBuilder
    private var overlay: some View {
        switch session.phase {
        case .connecting:
            ProgressView().tint(.white)
        case .failed:
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.yellow)
        default:
            EmptyView()
        }
    }
}

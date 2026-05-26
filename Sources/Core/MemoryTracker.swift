import Foundation

public struct MemoryTracker: Sendable {
    public static let shared = MemoryTracker()
    private init() {}

    public var currentRSSMB: Double {
        memoryInfo().resident
    }

    public var peakRSSMB: Double {
        memoryInfo().peak
    }

    private func memoryInfo() -> (resident: Double, peak: Double) {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info>.size / MemoryLayout<integer_t>.size)
        let kr = withUnsafeMutablePointer(to: &info) { ptr in
            ptr.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { intPtr in
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), intPtr, &count)
            }
        }
        guard kr == KERN_SUCCESS else { return (0, 0) }
        let resident = Double(info.resident_size) / 1_048_576
        let peak = Double(info.resident_size_peak) / 1_048_576
        return (resident, peak)
    }
}

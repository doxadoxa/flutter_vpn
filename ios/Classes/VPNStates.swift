import Foundation

public enum VPNStates: Int {
    case connecting = 1;
    case connected = 2;
    case disconnecting = 3;
    case disconnected = 0;
    case reasserting = 4;
}

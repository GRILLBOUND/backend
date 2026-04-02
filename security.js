const CONFIG = { MAX_SPEED: 150, MAX_Z: 5000, MIN_Z: -500 };

function validate3DMovement(player, msg) {
    const name = msg.name.toLowerCase();
    let axis = name.includes('_x') ? 'x' : name.includes('_y') ? 'y' : name.includes('_z') ? 'z' : null;
    if (!axis) return true;

    const newValue = parseFloat(msg.value);
    if (isNaN(newValue)) return false;

    // Boundary Check
    if (axis === 'z' && (newValue > CONFIG.MAX_Z || newValue < CONFIG.MIN_Z)) return false;

    // Euclidean Distance Check (Speed Calculation)
    const dx = axis === 'x' ? newValue - player.lastPos.x : 0;
    const dy = axis === 'y' ? newValue - player.lastPos.y : 0;
    const dz = axis === 'z' ? newValue - player.lastPos.z : 0;
    const dist = Math.sqrt(dx*dx + dy*dy + dz*dz);

    if (dist > CONFIG.MAX_SPEED) return false;

    player.lastPos[axis] = newValue;
    return true;
}

module.exports = { validate3DMovement };

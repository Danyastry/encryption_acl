package com.danyastry.encryption.core.hpke;

public enum HpkeMode {
    BASE(0x00),
    AUTH(0x02);

    private final int id;

    HpkeMode(int id) {
        this.id = id;
    }

    public int id() {
        return id;
    }

    public static HpkeMode of(int id) {
        for (HpkeMode mode : values()) {
            if (mode.id == id) {
                return mode;
            }
        }
        throw new IllegalArgumentException("Unsupported HPKE mode " + id);
    }
}

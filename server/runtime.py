"""跨模块共享的运行时句柄（避免循环导入）。"""
from __future__ import annotations

from typing import Optional

# 由 main.py 在启动时赋值；api.py 中按需引用
sip_protocol: Optional[object] = None

@echo off
title ScamShield AI Server
echo ===================================================
echo   Starting ScamShield Unified Application Server
echo   PromptWar Hackathon 2026
echo ===================================================
echo.
echo Application URL: http://127.0.0.1:8000
echo API Docs URL:    http://127.0.0.1:8000/docs
echo.
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
pause


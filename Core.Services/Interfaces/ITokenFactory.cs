﻿using System;
using System.Collections.Generic;
using System.Text;

namespace Core.Services.Interfaces
{
    public interface ITokenFactory
    {
        string GenerateToken(int size = 32);
    }
}

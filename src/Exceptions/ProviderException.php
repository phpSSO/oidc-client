<?php

namespace JuliusPC\OpenIDConnect\Exceptions;

use JuliusPC\OpenIDConnect\Exceptions\ClientException;

/**
 * OpenIDConnect Exception Class for exceptions caused by the OpenID Provider (OP).
 * It may be thrown in case of erratic behavior or missing features of the OP.
 */
class ProviderException extends ClientException
{

}

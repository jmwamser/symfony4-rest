<?php

namespace App\Controller\Api;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Encoder\JWTEncoderInterface;
use Symfony\Component\Routing\Annotation\Route;

use App\Controller\BaseController;

/**
 * Class TokenController
 */
class TokenController extends BaseController
{
    /**
     * @Route("/api/tokens", name="api_login", methods="POST")
     */
    public function new(Request $request, UserPasswordEncoderInterface $encoder, JWTEncoderInterface $jwtEncoder)
    {
        $user = $this->getDoctrine()
            ->getRepository('App:User')
            ->findOneBy(['username' => $request->getUser()]);

        if (!$user) {
            throw $this->createNotFoundException('No user');
        }

        $isValid = $encoder->isPasswordValid($user, $request->getPassword());

        if (!$isValid) {
            throw new BadCredentialsException();
        }

        $token = $jwtEncoder->encode(['username' => $user->getUsername()]);

        return new JsonResponse(['token' => $token], 201);
    }

    /**
     * @Route("/api/test", name="api_test", methods="GET")
     */
    public function woot(Request $request)
    {
        return new JsonResponse(['working' => true]);
    }
}

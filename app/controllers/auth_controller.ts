import type { HttpContext } from '@adonisjs/core/http'
import User from '#models/user'
import { schema, rules } from '@adonisjs/validator'

export default class AuthController {
    public async register({ request, response }: HttpContext) {
        // 1. Definir el esquema de validación para los datos de registro
        // Esto asegura que la información que recibimos sea válida y segura.
        const registerSchema = schema.create({
            // Validamos el nombre de usuario
            username: schema.string({ trim: true }, [
				rules.unique({ table: 'users', column: 'username' }),
                rules.minLength(3),
			]),
            // Validamos el correo electrónico
            email: schema.string({ trim: true }, [
                rules.email(),
                rules.unique({ table: 'users', column: 'email' }),
            ]),
            // Validamos la contraseña
            password: schema.string({ trim: true }, [
                rules.minLength(6),
                rules.confirmed('passwordConfirmation'), // Asegura que la contraseña y su confirmación coincidan
            ]),
        })

        // 2. Ejecutar la validación de la solicitud
        // 'request.validate' toma los datos de la solicitud y los compara con 'registerSchema'.
        // Si la validación falla, AdonisJS automáticamente detiene la ejecución.
        // y envía una respuesta HTTP 422 (Unprocessable Entity) con los errores detallados.
        // Si es exitosa, 'payload' contendrá los datos validados y limpiados.
        const payload = await request.validate({ schema: registerSchema })

        // 3. Crear el nuevo usuario en la base de datos
        // Usamos el modelo 'User' para interactuar con la tabla 'users'.
        // Los datos 'username', 'email' y 'password' se asignan directamente desde 'payload'.
        // Para 'passwordHash', le pasamos la contraseña en texto plano, pero NO se guarda así.
        // El hook 'beforeSave' en el modelo 'User' se encarga de hashear la contraseña antes de guardarla.
        const user = await User.create({
            username: payload.username,
            email: payload.email,
            passwordHash: payload.password, // La contraseña se hasheará automáticamente
            role: 'User',
        })

        // 4. Autenticar al usuario recién registrado y generar un token de acceso JWT.
        // 'response.auth.use('api')' accede al sistema de autenticación de AdonisJS.
        // especificando que usaremos el guard 'api'.
        // '.login(user)' inicia una sesión para el usuario recién creado y genera un token de acceso JWT.
        // 'expiresIn: '10 days' define la duración del token.
        const token = await response.auth.use('api').login(user, {
            expiresIn: '10 days',
        })

        // 5. Enviar la respuesta de éxito al cliente
        // 'response.created()' envía una respuesta HTTP 201 (Created) al cliente.
        // Este es el código de estado estándar para indicar que un recurso se ha creado exitosamente.
        // Incluimos un mensaje, la información del usuario (serializada para ocultar datos sensibles),
        // y el token de acceso para que el frontend pueda usarlo en futuras solicitudes protegidas.
        return response.created({
            message: 'Usuario registrado exitosamente',
            user: user.serialize(),
            token
        })
    }
}